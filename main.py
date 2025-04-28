import os
import logging
import base64
import json
# import json # Removed unused import
from typing import Dict, Optional, Tuple
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings
from supabase import create_client, Client
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from doubleratchet import DoubleRatchet
from doubleratchet.types import EncryptedMessage
from doubleratchet.recommended import diffie_hellman_ratchet_curve25519 as dhr25519
from postgrest.exceptions import APIError
from doubleratchet import DoubleRatchet
from doubleratchet.diffie_hellman_ratchet import DuplicateMessageException, DoSProtectionException
from doubleratchet.aead import AuthenticationFailedException

from typing import Optional
from doubleratchet.types import Header, EncryptedMessage  

class SecureChatRatchet(DoubleRatchet):
    """
    Small helper that lets you fallback to a static AD when one is
    not supplied by the caller.
    """
    def __init__(self, *, static_ad: bytes = b"", **kw):
        self._static_ad = static_ad
        super().__init__(**kw)

    # must accept 3 positional arguments!
    def _build_associated_data(
        self,
        associated_data: bytes | None,
        header: Header
    ) -> bytes:
        return associated_data or self._static_ad
    
# Added imports for detailed DR config
from doubleratchet.recommended import (
    kdf_hkdf,               # HKDF-SHA256
    kdf_separate_hmacs,     # HMAC-SHA256/256
    aead_aes_hmac           # AES-256-GCM + HMAC
)
from doubleratchet.recommended.crypto_provider import HashFunction


# --- Environment Variable Loading ---
class Settings(BaseSettings):
    supabase_url: str
    supabase_service_role_key: str

    class Config:
        env_file = '.env'
        extra = 'ignore'

settings = Settings()

# ------------------------------------------------------------------ #
# 1.  CONFIGURE which DH ratchet the lib should use (Curve25519)     #
# ------------------------------------------------------------------ #
# DR_CONFIG = {
#     "diffie_hellman_ratchet_class": dhr25519.DiffieHellmanRatchet,
# }

# --- Detailed DR Configuration (v0.9.x+) ---
class RootChainKDF(kdf_hkdf.KDF):
    _get_hash_function = staticmethod(lambda: HashFunction.SHA_256)
    _get_info          = staticmethod(lambda: b"SecureChat Root KDF")
class MsgChainKDF(kdf_separate_hmacs.KDF):
    _get_hash_function = staticmethod(
        lambda: HashFunction.SHA_512_256  # Updated from SHA_256_256
    )
class AEAD(aead_aes_hmac.AEAD):
    _get_hash_function = staticmethod(lambda: HashFunction.SHA_256)
    _get_info          = staticmethod(lambda: b"SecureChat AEAD")

DR_CONFIG = {
    "diffie_hellman_ratchet_class": dhr25519.DiffieHellmanRatchet,
    "root_chain_kdf":               RootChainKDF,
    "message_chain_kdf":            MsgChainKDF,
    "message_chain_constant":       b"\x01\x02",
    "dos_protection_threshold":     2000,
    "max_num_skipped_message_keys": 4000,
    "aead":                         AEAD,
}

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- FastAPI App Initialization ---
app = FastAPI()

# --- CORS Configuration ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "https://dds-secure-chat-web.vercel.app"],  # Adjust for your frontend origin
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Supabase Client (Synchronous) ---
supabase: Optional[Client] = None

@app.on_event("startup")
def startup_event():
    global supabase
    logger.info("Initializing Supabase client...")
    supabase = create_client(settings.supabase_url, settings.supabase_service_role_key)
    logger.info("Supabase client initialized.")
    # You might want to check DB connection here or ensure tables exist

@app.on_event("shutdown")
def shutdown_event():
    logger.info("Supabase client cleanup (if any needed).")
    pass

def get_supabase_client() -> Client:
    if supabase is None:
        # This should ideally not happen if startup event works correctly
        raise HTTPException(status_code=503, detail="Supabase client not initialized")
    return supabase

# --- Base64 Helpers ---
def bytes_to_base64(data: bytes) -> str:
    return base64.b64encode(data).decode('utf-8')

def base64_to_bytes(b64_str: str) -> bytes:
    try:
        return base64.b64decode(b64_str)
    except base64.binascii.Error as e:
        logger.error(f"Base64 decode error: {e}, input: {b64_str[:20]}...")
        raise ValueError(f"Invalid base64 string: {e}") from e


# --- Pydantic Models ---
class GenerateKeysRequest(BaseModel):
    user_id: str = Field(..., description="The unique identifier for the user.")

class GenerateKeysResponse(BaseModel):
    success: bool
    message: str
    public_key_b64: Optional[str] = None

class InitiateSessionRequest(BaseModel):
    sender_id: str
    recipient_id: str

class InitiateSessionResponse(BaseModel):
    success: bool
    message: str
    initial_sender_state_saved: bool = False
    # Include the first encrypted message generated during initiation (optional)
    initial_packet_header_b64: Optional[str] = None
    initial_packet_ciphertext_b64: Optional[str] = None

class EncryptRequest(BaseModel):
    sender_id: str
    recipient_id: str
    plaintext: str

class EncryptResponse(BaseModel):
    header_b64: str
    ciphertext_b64: str

class DecryptRequest(BaseModel):
    recipient_id: str # The user receiving the message
    sender_id: str    # The user who sent the message
    header_b64: str
    ciphertext_b64: str

class DecryptResponse(BaseModel):
    plaintext: str
    already_decrypted: bool

class PublicKeyResponse(BaseModel):
    user_id: str
    public_key_b64: str


# --- Database Interaction Functions (Synchronous) ---

def store_user_keys(user_id: str, public_key: bytes, private_key: bytes, db: Client):
    """Stores user's identity keys (X25519)."""
    logger.info(f"Storing keys for user {user_id}")
    public_key_b64 = bytes_to_base64(public_key)
    private_key_b64 = bytes_to_base64(private_key) # WARNING: Storing private keys like this is insecure. Encrypt at rest!
    try:
        db.table("user_keys").upsert(
            {
                "user_id": user_id,
                "identity_public_key_b64": public_key_b64,
                "identity_private_key_b64": private_key_b64,
            },
            on_conflict="user_id"
        ).execute()
        logger.info(f"Keys stored successfully for user {user_id}")
    except Exception as e:
        logger.error(f"Failed to store keys for {user_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Database error storing keys: {e}")

def fetch_user_keys(user_id: str, db: Client) -> Optional[dict]:
    """Fetches user's public and private identity keys."""
    logger.info(f"Fetching keys for user {user_id}")
    try:
        q = db.table("user_keys")\
              .select("identity_public_key_b64,identity_private_key_b64")\
              .eq("user_id", user_id)\
              .limit(1) # Use limit(1) instead of maybe_single()
        resp = q.execute()

        # resp.data is [] when no rows match
        if not resp or not resp.data:
            logger.warning(f"No keys found for user {user_id} (limit(1) returned no data)")
            return None

        # If we reach here, resp.data contains one row
        row = resp.data[0]
        return {
            "public": base64_to_bytes(row["identity_public_key_b64"]),
            "private": base64_to_bytes(row["identity_private_key_b64"]),
        }
    # No longer need to catch specific APIError for maybe_single behavior
    # except APIError as e: ...
    except Exception as e:
        logger.error(f"Unexpected error fetching keys for {user_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error fetching keys: {e}")

def fetch_public_key(user_id: str, db: Client) -> Optional[bytes]:
    """Fetches only the public identity key for a user."""
    logger.info(f"Fetching public key for user {user_id}")
    try:
        q = db.table("user_keys")\
              .select("identity_public_key_b64")\
              .eq("user_id", user_id)\
              .limit(1) # Use limit(1)
        resp = q.execute()

        if not resp or not resp.data:
            logger.warning(f"No public key found for user {user_id} (limit(1) returned no data)")
            return None

        # If we reach here, resp.data contains one row
        row = resp.data[0]
        if not row.get("identity_public_key_b64"):
             logger.warning(f"Public key data is null/missing for user {user_id} despite row existing")
             return None
        return base64_to_bytes(row["identity_public_key_b64"])
    # No longer need to catch specific APIError for maybe_single behavior
    except Exception as e:
        logger.error(f"Failed to fetch public key for {user_id}: {e}", exc_info=True) # Added exc_info
        raise HTTPException(status_code=500, detail=f"Database error fetching public key: {e}")

def load_ratchet_state(user_id: str, peer_id: str, db: Client) -> Optional[SecureChatRatchet]:
    """Loads and deserializes the DoubleRatchet state from Supabase via JSON."""
    logger.info(f"Loading ratchet state for {user_id} <-> {peer_id}")
    try:
        # Fetch the base64 encoded JSON string using limit(1)
        q = db.table("ratchet_states")\
              .select("state_b64")\
              .eq("user_id", user_id)\
              .eq("peer_id", peer_id)\
              .limit(1)
        response = q.execute()

        # Check if data list is empty
        if not response or not response.data:
            logger.info(f"No existing ratchet state found for {user_id} <-> {peer_id} (limit(1) returned no data)")
            return None

        # Process the first (and only) row
        row = response.data[0]
        state_b64 = row.get("state_b64")
        if not state_b64:
             logger.warning(f"Ratchet state data is null/missing for {user_id} <-> {peer_id} despite row existing")
             return None

        # Decode base64 -> bytes -> json string -> dict
        json_str = base64_to_bytes(state_b64).decode('utf-8')
        json_dict = json.loads(json_str)

        # Deserialize from dict using SecureChatRatchet.from_json
        ratchet_obj = SecureChatRatchet.from_json(
            json_dict,
            **DR_CONFIG
        )
        logger.info(f"Successfully loaded and deserialized ratchet state for {user_id} <-> {peer_id}")
        return ratchet_obj

    except json.JSONDecodeError as json_err:
        logger.error(f"Failed to decode JSON state for {user_id} <-> {peer_id}: {json_err}", exc_info=True)
        raise HTTPException(status_code=500, detail="Database error: Corrupted ratchet state.")
    except Exception as e:
        logger.error(f"Exception during loading ratchet state for {user_id} <-> {peer_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error loading ratchet state: {e}")

def save_ratchet_state(user_id: str, peer_id: str,
                       ratchet: SecureChatRatchet, db: Client) -> None:
    """Serialise ratchet -> dict -> JSON string -> base64 -> DB."""
    logger.info(f"Saving ratchet state for {user_id} <-> {peer_id}")
    try:
        # 1. Get dict from ratchet
        state_dict = ratchet.json
        # 2. Dump dict to JSON string
        state_json_str = json.dumps(state_dict)
        # 3. Encode JSON string to bytes, then base64 encode bytes
        state_b64 = bytes_to_base64(state_json_str.encode('utf-8'))

        db.table("ratchet_states").upsert(
            {"user_id": user_id,
             "peer_id": peer_id,
             "state_b64": state_b64},
            on_conflict="user_id,peer_id"
        ).execute()
        logger.info(f"Ratchet state saved successfully for {user_id} <-> {peer_id}")
    except Exception as e:
        logger.error(f"Error saving ratchet state for {user_id} <-> {peer_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error saving ratchet state: {e}")

# Helper to ensure bytes conversion
def as_bytes(obj: object) -> bytes:
    """
    Convert Double-Ratchet helper objects to raw bytes.
      * bytes / bytearray  -> returned as-is (copy for bytearray)
      * doubleratchet.types.Header -> custom serialisation
      * anything implementing  __bytes__ -> use that
    """
    if isinstance(obj, bytes):
        return obj
    if isinstance(obj, bytearray):
        return bytes(obj)           # copy
    if isinstance(obj, Header):
        # Header is (ratchet_pub: bytes, pn: int, n: int)
        return (
            obj.ratchet_pub +
            obj.previous_sending_chain_length.to_bytes(4, "big") +
            obj.sending_chain_length.to_bytes(4, "big")
        )
    if hasattr(obj, "__bytes__"):
        return obj.__bytes__()
    raise TypeError(f"Cannot obtain bytes from type {type(obj).__name__}")

# NEW: Helper to reconstruct Header from 40-byte wire format
def header_from_bytes(buf: bytes) -> Header:
    """Convert the 40-byte header we put on the wire back into a Header object."""
    if len(buf) != 40:
        raise ValueError(f"Header must be 40 bytes, got {len(buf)}")
    ratchet_pub                       = buf[:32]
    previous_sending_chain_length     = int.from_bytes(buf[32:36], "big")
    sending_chain_length              = int.from_bytes(buf[36:40], "big")
    return Header(
        ratchet_pub                    = ratchet_pub,
        previous_sending_chain_length  = previous_sending_chain_length,
        sending_chain_length           = sending_chain_length,
    )

# --- DH Key Exchange Helper (Used for Initial Shared Secret) ---
def perform_dh_exchange(private_key: x25519.X25519PrivateKey, public_key_bytes: bytes) -> bytes:
    """Performs X25519 Diffie-Hellman exchange."""
    try:
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(public_key_bytes)
        shared_key = private_key.exchange(peer_public_key)
        # Derive a key using HKDF - recommended practice
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32, # 256 bits for AES-256 GCM used by doubleratchet
            salt=None,
            info=b'doubleratchet-shared-secret',
        ).derive(shared_key)
        return derived_key
    except Exception as e:
        logger.error(f"Diffie-Hellman exchange failed: {e}")
        raise ValueError("DH exchange failed") from e


# --- API Routes ---

@app.get("/")
def read_root():
    return {"message": "Secure Chat Backend using FastAPI and DoubleRatchet"}

@app.post("/api/keys/generate", response_model=GenerateKeysResponse)
def generate_keys(req: GenerateKeysRequest, db: Client = Depends(get_supabase_client)):
    """
    Generates X25519 identity key pair for a user and stores it.
    This is a prerequisite for initiating sessions.
    """
    logger.info(f"API: /keys/generate called for user {req.user_id}")

    # 1. Check if keys already exist
    existing_keys = fetch_user_keys(req.user_id, db)
    if existing_keys:
        logger.warn(f"Keys already exist for user {req.user_id}. Generation skipped.")
        pub_key = x25519.X25519PublicKey.from_public_bytes(existing_keys["public"])
        return GenerateKeysResponse(
            success=True,
            message="Keys already exist for this user.",
            public_key_b64=bytes_to_base64(
                pub_key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
            )
        )

    # 2. Generate new X25519 keys
    logger.info(f"Generating new keys for user {req.user_id}...")
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()

    # 3. Serialize keys for storage (using Raw format for simplicity)
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption() # WARNING: Insecure for production
    )

    # 4. Store keys in Supabase
    try:
        store_user_keys(req.user_id, public_key_bytes, private_key_bytes, db)
        return GenerateKeysResponse(
            success=True,
            message="X25519 keys generated and stored successfully.",
            public_key_b64=bytes_to_base64(public_key_bytes)
        )
    except HTTPException as http_exc:
        raise http_exc # Re-raise DB errors
    except Exception as e:
        logger.exception(f"Unexpected error generating keys for {req.user_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to generate keys: {e}")

@app.get("/api/keys/public/{user_id}", response_model=PublicKeyResponse)
def get_public_key(user_id: str, db: Client = Depends(get_supabase_client)):
    """Fetches the public identity key for a user."""
    logger.info(f"API: /keys/public called for user {user_id}")
    public_key_bytes = fetch_public_key(user_id, db)
    if not public_key_bytes:
        raise HTTPException(status_code=404, detail=f"Public key not found for user {user_id}")

    return PublicKeyResponse(
        user_id=user_id,
        public_key_b64=bytes_to_base64(public_key_bytes)
    )

@app.post("/api/sessions/initiate", response_model=InitiateSessionResponse)
# Mark as async since we will await crypto operations
async def initiate_session(req: InitiateSessionRequest, db: Client = Depends(get_supabase_client)):
    """
    Initiates a DoubleRatchet session between two users.
    The *sender* (Alice in library terms) calls this.
    Performs DH exchange, creates the initial ratchet state for the sender,
    and generates the very first encrypted message (initial packet).
    """
    sender_id = req.sender_id
    recipient_id = req.recipient_id
    logger.info(f"API: /sessions/initiate called for {sender_id} -> {recipient_id}")

    # 1. Check if session already initiated (sender's perspective)
    existing_state = load_ratchet_state(sender_id, recipient_id, db)
    if existing_state:
        logger.warn(f"Session already initiated for {sender_id} -> {recipient_id}. Skipping.")
        # If state exists, we can't provide the initial packet again
        return InitiateSessionResponse(
            success=True,
            message="Session already initiated.",
            initial_sender_state_saved=True)

    # 2. Fetch sender's private key and recipient's public key
    sender_keys = fetch_user_keys(sender_id, db)
    recipient_public_key = fetch_public_key(recipient_id, db)

    if not sender_keys or not sender_keys.get("private"):
        raise HTTPException(status_code=404, detail=f"Sender keys not found for {sender_id}. Generate keys first.")
    if not recipient_public_key:
        raise HTTPException(status_code=404, detail=f"Recipient public key not found for {recipient_id}. Recipient must generate keys first.")

    # 3. Perform Diffie-Hellman exchange to get the shared secret (SK)
    try:
        sender_private_key_obj = x25519.X25519PrivateKey.from_private_bytes(sender_keys["private"])
        sk = perform_dh_exchange(sender_private_key_obj, recipient_public_key)
        logger.info(f"DH exchange successful for {sender_id} -> {recipient_id}")
    except ValueError as e:
         raise HTTPException(status_code=500, detail=f"Failed to perform DH exchange: {e}")
    except Exception as e: # Catch broader crypto errors
        logger.exception(f"DH exchange failed unexpectedly for {sender_id} -> {recipient_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"DH exchange failed: {e}")

    # 4. Initialize Sender's Ratchet (Alice) and encrypt the first message
    try:
        # Use the raw recipient public key bytes fetched earlier
        # recipient_public_key_obj = x25519.X25519PublicKey.from_public_bytes(recipient_public_key) # No need to create object here

        # `encrypt_initial_message` bootstraps the sender's ratchet (Alice)
        # and creates the first message for the recipient (Bob) to use for their bootstrap.
        sender_ratchet, first_packet = await SecureChatRatchet.encrypt_initial_message(
            shared_secret         = sk,
            recipient_ratchet_pub = recipient_public_key,
            message               = b"(initial session packet)",
            associated_data       = f"{sender_id}:{recipient_id}".encode(),
            **DR_CONFIG
        )
        logger.info(f"Sender's ratchet initialized and first packet encrypted for {sender_id} -> {recipient_id}")
    except Exception as e:
        logger.exception(f"Error during initial message encryption {sender_id} -> {recipient_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to initialize session and encrypt first message: {e}")

    # 5. Serialize and save the sender's ratchet state
    try:
        save_ratchet_state(sender_id, recipient_id, sender_ratchet, db)
        return InitiateSessionResponse(
            success=True,
            message=f"Session initiated successfully for {sender_id} -> {recipient_id}. Sender state saved.",
            initial_sender_state_saved=True,
            initial_packet_header_b64=bytes_to_base64(as_bytes(first_packet.header)),
            initial_packet_ciphertext_b64=bytes_to_base64(first_packet.ciphertext)
        )
    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        logger.exception(f"Error saving sender state after initiation {sender_id} -> {recipient_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to save initial sender state: {e}")

@app.post("/api/messages/encrypt", response_model=EncryptResponse)
# Mark as async since we will await crypto operations
async def encrypt_message(req: EncryptRequest, db: Client = Depends(get_supabase_client)):
    """Encrypts a message using the DoubleRatchet protocol."""
    sender_id = req.sender_id
    recipient_id = req.recipient_id
    plaintext = req.plaintext
    logger.info(f"API: /messages/encrypt from {sender_id} to {recipient_id}")

    # 1. Load sender's ratchet object for this recipient
    sender_ratchet = load_ratchet_state(sender_id, recipient_id, db)
    if not sender_ratchet:
        raise HTTPException(status_code=404, detail=f"Session not initiated for {sender_id} -> {recipient_id}. Initiate session first.")

    # 2. Encrypt the message (Ratchet already loaded)
    try:
        # --- Logging AD ---
        # ad_encrypt = f"{sender_id}:{recipient_id}".encode('utf-8')
        # logger.info(f"Encrypting with AD: {ad_encrypt!r} for {sender_id} -> {recipient_id}")
        # --- End Logging ---
        encrypted_packet: EncryptedMessage = await sender_ratchet.encrypt_message(
            plaintext.encode('utf-8'),
            associated_data=f"{sender_id}:{recipient_id}".encode('utf-8') # Use the logged variable
        )
        logger.info(f"Message encrypted by {sender_id} for {recipient_id}.")
    except Exception as e:
        logger.exception(f"Encryption failed for {sender_id} -> {recipient_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Encryption failed: {e}")

    # 3. Serialize and save the updated sender state
    try:
        save_ratchet_state(sender_id, recipient_id, sender_ratchet, db)
    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        logger.exception(f"Failed to save updated sender state for {sender_id} -> {recipient_id} after encryption: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to save updated sender state: {e}")

    # 4. Return the encrypted message
    return EncryptResponse(
        header_b64=bytes_to_base64(as_bytes(encrypted_packet.header)),
        ciphertext_b64=bytes_to_base64(encrypted_packet.ciphertext)
    )

@app.post("/api/messages/decrypt", response_model=DecryptResponse)
# Mark as async since we will await crypto operations
async def decrypt_message(req: DecryptRequest, db: Client = Depends(get_supabase_client)):
    """Decrypts a message using the DoubleRatchet protocol. Handles both initial and subsequent messages."""
    recipient_id = req.recipient_id
    sender_id = req.sender_id
    logger.info(f"API: /messages/decrypt for {recipient_id} from {sender_id}")

    # 1. Decode header and ciphertext and create EncryptedMessage object
    try:
        header_bytes = base64_to_bytes(req.header_b64)
        ciphertext_bytes = base64_to_bytes(req.ciphertext_b64)
        # Reconstruct Header object using the new helper
        header_obj = header_from_bytes(header_bytes)
        # Pass the Header object to EncryptedMessage
        incoming_message = EncryptedMessage(header=header_obj, ciphertext=ciphertext_bytes)
    except ValueError as e:
         raise HTTPException(status_code=400, detail=f"Invalid base64 encoding in message: {e}")
    except Exception as e: # Catch potential errors during Header.from_bytes
        logger.exception(f"Error reconstructing Header object for {recipient_id} <- {sender_id}: {e}", exc_info=True)
        raise HTTPException(status_code=400, detail="Invalid message header format.")

    # 2. Load recipient's ratchet object for this sender
    recipient_ratchet = load_ratchet_state(recipient_id, sender_id, db)

    # 3. Initialize or Decrypt
    plaintext_bytes: Optional[bytes] = None
    newly_initialized = False
    duplicate = False # Initialize here

    # --- A. First Message Received ---
    if not recipient_ratchet:
        # First message received - initialize recipient ratchet
        logger.info(f"First message received by {recipient_id} from {sender_id}. Initializing recipient ratchet.")
        recipient_keys = fetch_user_keys(recipient_id, db)
        sender_public_key = fetch_public_key(sender_id, db)

        if not recipient_keys or not recipient_keys.get("private"):
             raise HTTPException(status_code=404, detail=f"Recipient keys not found for {recipient_id}.")
        if not sender_public_key:
             raise HTTPException(status_code=404, detail=f"Sender public key not found for {sender_id}.")

        try:
            # Perform DH exchange to get the shared secret
            recipient_private_key_obj = x25519.X25519PrivateKey.from_private_bytes(recipient_keys["private"])
            # Need sender's public key as an object
            sender_public_key_obj = x25519.X25519PublicKey.from_public_bytes(sender_public_key)

            sk = perform_dh_exchange(recipient_private_key_obj, sender_public_key)
            logger.info(f"DH exchange successful for {recipient_id} <- {sender_id} (on receive)")

            # `decrypt_initial_message` bootstraps the recipient (Bob) and decrypts the first message
            # Use SecureChatRatchet instead of DoubleRatchet
            # --- Logging AD ---
            # ad_decrypt_initial = f"{sender_id}:{recipient_id}".encode()
            # logger.info(f"Decrypting initial message with AD: {ad_decrypt_initial!r} for {recipient_id} <- {sender_id}")
            # --- End Logging ---
            recipient_ratchet, plaintext_bytes = await SecureChatRatchet.decrypt_initial_message(
                shared_secret     = sk,
                own_ratchet_priv  = recipient_private_key_obj.private_bytes(
                    encoding = serialization.Encoding.Raw,
                    format   = serialization.PrivateFormat.Raw,
                    encryption_algorithm = serialization.NoEncryption()
                ),
                message           = incoming_message,
                associated_data   = f"{sender_id}:{recipient_id}".encode(), # Use the logged variable
                **DR_CONFIG
            )
            logger.info(f"Recipient's ratchet initialized and initial message decrypted for {recipient_id} <- {sender_id}")
            newly_initialized = True # Mark that state needs to be saved for the first time

        except ValueError as e:
             raise HTTPException(status_code=500, detail=f"Failed to perform DH exchange during initial decryption: {e}")
        except Exception as e:
            logger.exception(f"Error initializing recipient\'s ratchet {recipient_id} <- {sender_id}: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=f"Failed to initialize recipient ratchet: {e}")

    else:
        # `load_ratchet_state()` already returned a *live* SecureChatRatchet
        # object.  No extra deserialisation step is required.
        logger.info(
            f"Recipient ratchet already loaded for {recipient_id} <- {sender_id}"
        )

    # Ensure ratchet is available (either loaded or newly initialized)
    if not recipient_ratchet:
        # This path should ideally not be reached if initialization worked,
        # but included for safety.
        logger.error(f"Ratchet object unavailable after load/init attempt for {recipient_id} <- {sender_id}")
        raise HTTPException(status_code=500, detail="Recipient ratchet could not be initialized or loaded.")

    # --- B. Subsequent Message Received --- (Or first message if newly initialized)
    # Decrypt normally using the already loaded/initialized ratchet
    if not newly_initialized:
        try:
            # --- Logging AD ---
            # ad_decrypt = f"{sender_id}:{recipient_id}".encode('utf-8')
            # logger.info(f"Decrypting subsequent message with AD: {ad_decrypt!r} for {recipient_id} <- {sender_id}")
            # --- End Logging ---
            plaintext_bytes = await recipient_ratchet.decrypt_message(
                incoming_message,
                associated_data=f"{sender_id}:{recipient_id}".encode('utf-8') # Use the logged variable
            )
            logger.info(f"Subsequent message decrypted successfully for {recipient_id} from {sender_id}")
        except DuplicateMessageException:
            # The ratchet has already consumed that header.
            # We don't get the plaintext again from the library here,
            # but the state update will still be saved.
            logger.warning(
                f"Duplicate packet detected by library for {recipient_id} <- {sender_id}."
            )
            plaintext_bytes = b"" # Indicate duplicate, no plaintext available now
            duplicate = True      # Set the flag
        except AuthenticationFailedException as auth_err: # Catch specific auth error
             logger.error(f"Authentication failed for {recipient_id} <- {sender_id}: {auth_err}", exc_info=True)
             # Provide a clearer error message to the client
             raise HTTPException(status_code=400, detail=f"Decryption failed: Authentication error. The message may be corrupt, out-of-order, or session state is desynchronized.")
        except DoSProtectionException as dos_err:
             logger.error(f"DoS protection triggered during decryption for {recipient_id} <- {sender_id}: {dos_err}", exc_info=True)
             raise HTTPException(status_code=429, detail=f"Decryption failed: Too many skipped messages. {dos_err}")
        except Exception as e:
            logger.exception(f"Decryption failed unexpectedly for {recipient_id} from {sender_id}: {e}", exc_info=True)
            # Generic error for other potential DR issues or unexpected errors
            raise HTTPException(status_code=400, detail=f"Decryption failed: An unexpected error occurred.")

    # 4. Check if decryption was successful (plaintext_bytes should not be None unless duplicate)
    if plaintext_bytes is None and not duplicate: # Ensure we don't raise 500 for duplicates
        # This case might happen if initialization failed silently or decryption failed unexpectedly
        logger.error(f"Decryption resulted in None (and not a duplicate) for {recipient_id} from {sender_id}. Ratchet state: {recipient_ratchet}")
        raise HTTPException(status_code=500, detail="Decryption failed unexpectedly.")
    else:
        # Decode only if not a duplicate (where we set it to b"")
        plaintext = plaintext_bytes.decode('utf-8') if not duplicate else ""

    # 5. Serialize and save the updated recipient state
    # State should be saved even if it was a duplicate, as the internal counters might have updated
    try:
        save_ratchet_state(recipient_id, sender_id, recipient_ratchet, db)
    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        logger.exception(f"Failed to save updated recipient state for {recipient_id} <- {sender_id} after decryption: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to save updated recipient state: {e}")

    # 6. Return the plaintext and the flag
    return DecryptResponse(
        plaintext=plaintext,
        already_decrypted=duplicate # Use the flag here
    )

# --- Uvicorn Runner ---
# Remove this block for Vercel deployment
# if __name__ == "__main__":
#     import uvicorn
#     uvicorn.run("main:app", host="0.0.0.0", port=3001, reload=True, log_level="info") 