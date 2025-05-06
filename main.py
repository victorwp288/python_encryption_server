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
from postgrest.exceptions import APIError

from typing import Optional


class PreKeyBundleRequest(BaseModel):
    userId: str
    registrationId: int
    identityKey: str                # base64‑encoded identity public key
    signedPreKeyId: int
    signedPreKeyPublicKey: str      # base64‑encoded
    signedPreKeySignature: str      # base64‑encoded
    preKeyId: int
    preKeyPublicKey: str            # base64‑encoded
    
	
# --- Environment Variable Loading ---
class Settings(BaseSettings):
    supabase_url: str
    supabase_service_role_key: str

    class Config:
        env_file = '.env'
        extra = 'ignore'

settings = Settings()

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
# class InitiateSessionRequest(BaseModel):
#     ...

# class PublicKeyResponse(BaseModel):
#     user_id: str
#     public_key_b64: str


# --- Response Model for Bundle Retrieval --- #
class PreKeyBundleResponse(BaseModel):
    registrationId: int
    identityKey: str                # base64‑encoded
    signedPreKeyId: int
    signedPreKeyPublicKey: str      # base64‑encoded
    signedPreKeySignature: str      # base64‑encoded
    preKeyId: int                   # Assuming only one pre-key is stored per bundle in this table
    preKeyPublicKey: str            # base64‑encoded


# --- API Routes ---

@app.get("/")
def read_root():
    return {"message": "Secure Chat Backend using FastAPI and DoubleRatchet"}

@app.post("/api/signal/store-bundle")
def store_prekey_bundle(
    req: PreKeyBundleRequest,
    db: Client = Depends(get_supabase_client)
):
    """
    Stores (upserts) this user's public PreKey bundle into Supabase.
    Front‑end will call this once after signup.
    """
    # Build the row to upsert
    row = {
        "user_id":                     req.userId,
        "registration_id":             req.registrationId,
        "identity_key_b64":            req.identityKey,
        "signed_prekey_id":            req.signedPreKeyId,
        "signed_prekey_public_key_b64":req.signedPreKeyPublicKey,
        "signed_prekey_signature_b64": req.signedPreKeySignature,
        "prekey_id":                   req.preKeyId,
        "prekey_public_key_b64":       req.preKeyPublicKey,
    }

    try:
        # Supabase Python upsert example :contentReference[oaicite:0]{index=0}
        db.table("prekey_bundles")\
          .upsert(row, on_conflict="user_id")\
          .execute()
    except Exception as e:
        # Log and return HTTP 500 on failure
        logger.error(f"Failed to store prekey bundle for {req.userId}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to store PreKey bundle")

    return {"success": True}

# --- NEW: Endpoint to Fetch PreKey Bundle --- #
@app.get("/api/signal/bundle/{user_id}", response_model=PreKeyBundleResponse)
def get_prekey_bundle(user_id: str, db: Client = Depends(get_supabase_client)):
    """
    Fetches the publicly available PreKeyBundle for a given user_id.
    Clients need this to initiate a secure session.
    """
    logger.info(f"API: /signal/bundle called for user {user_id}")
    try:
        # Query the prekey_bundles table
        query = db.table("prekey_bundles") \
                  .select("registration_id, identity_key_b64, signed_prekey_id, signed_prekey_public_key_b64, signed_prekey_signature_b64, prekey_id, prekey_public_key_b64") \
                  .eq("user_id", user_id) \
                  .limit(1) # Ensure we get at most one record

        response = query.execute()

        # Check if data was found
        if not response or not response.data:
            logger.warning(f"PreKeyBundle not found for user_id: {user_id}")
            raise HTTPException(status_code=404, detail=f"PreKeyBundle not found for user {user_id}")

        # Extract the first (and only) record
        bundle_data = response.data[0]

        # Map database columns to Pydantic model fields
        # Note: Adjust field names if they differ between DB and model
        return PreKeyBundleResponse(
            registrationId=bundle_data["registration_id"],
            identityKey=bundle_data["identity_key_b64"],
            signedPreKeyId=bundle_data["signed_prekey_id"],
            signedPreKeyPublicKey=bundle_data["signed_prekey_public_key_b64"],
            signedPreKeySignature=bundle_data["signed_prekey_signature_b64"],
            preKeyId=bundle_data["prekey_id"],
            preKeyPublicKey=bundle_data["prekey_public_key_b64"]
        )

    except APIError as api_error:
        logger.error(f"Supabase API error fetching bundle for {user_id}: {api_error}", exc_info=True)
        # Check for specific errors if needed, otherwise return 500
        raise HTTPException(status_code=500, detail=f"Database error fetching bundle: {api_error.message}")
    except Exception as e:
        logger.error(f"Unexpected error fetching bundle for {user_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Server error fetching bundle: {e}")

# --- Removed /api/keys/public/{user_id} endpoint --- #

# --- Removed load_ratchet_state function --- #

# --- Uvicorn Runner ---
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=3001, reload=True, log_level="info")