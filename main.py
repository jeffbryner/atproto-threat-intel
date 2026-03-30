import json
import logging
import os
import hashlib
import asyncio
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Security, WebSocket, WebSocketDisconnect
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field
from google.cloud import firestore, kms, pubsub_v1
from google.api_core import exceptions

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="ISLF Threat-Intel Gateway")

# Configuration (In a real app, use pydantic-settings or env vars)
PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT", "prj-atproto-threat-intel")
FIRESTORE_COLLECTION = "sponsored_keys"
PUBSUB_TOPIC = "threat-intel-firehose"
# Expected: projects/*/locations/*/keyRings/*/cryptoKeys/*/cryptoKeyVersions/*
KMS_KEY_NAME = os.getenv("KMS_KEY_NAME") 

# Initialize GCP Clients
db = firestore.Client(project=PROJECT_ID)
publisher = pubsub_v1.PublisherClient()
kms_client = kms.KeyManagementServiceClient()

# Security Header
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

class ThreatIndicator(BaseModel):
    indicator: str
    type: str # ipv4, url, hash, etc.
    description: Optional[str] = None
    via: str = "did:plc:islf-anonymous-member"
    createdAt: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

async def validate_api_key(api_key: str) -> bool:
    """Validates the SHA-256 hash of the API key against Firestore."""
    if not api_key:
        return False
    
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    
    try:
        # Check Firestore for a document where the ID is the hash of the key
        doc_ref = db.collection(FIRESTORE_COLLECTION).document(key_hash)
        doc = doc_ref.get()
        return doc.exists
    except exceptions.GoogleAPICallError as e:
        logger.error(f"Firestore error: {e}")
        return False

@app.post("/v1/submit")
async def submit_indicator(
    indicator: ThreatIndicator, 
    api_key: str = Security(api_key_header)
):
    """
    Validates the API key, signs the indicator with KMS, and publishes to Pub/Sub.
    """
    if not await validate_api_key(api_key):
        raise HTTPException(status_code=403, detail="Invalid API Key")

    # 1. Prepare the record (Anonymize/Format)
    record = indicator.model_dump()
    record["via"] = "did:plc:islf-anonymous-member" # Ensure anonymity
    
    payload = json.dumps(record, sort_keys=True).encode("utf-8")

    # 2. Sign with KMS
    if not KMS_KEY_NAME:
        logger.warning("KMS_KEY_NAME not configured, skipping signature for POC")
        signature = b"unsigned-poc-signature"
    else:
        try:
            response = kms_client.asymmetric_sign(
                request={
                    "name": KMS_KEY_NAME,
                    "digest": {"sha256": hashlib.sha256(payload).digest()}
                }
            )
            signature = response.signature
        except Exception as e:
            logger.error(f"KMS Signing error: {e}")
            raise HTTPException(status_code=500, detail="Signing failed")

    # 3. Construct final signed message
    signed_message = {
        "record": record,
        "signature": signature.hex(),
        "alg": "EC_SIGN_P256_SHA256"
    }

    # 4. Broadcast to Pub/Sub
    topic_path = publisher.topic_path(PROJECT_ID, PUBSUB_TOPIC)
    future = publisher.publish(topic_path, json.dumps(signed_message).encode("utf-8"))
    message_id = future.result()

    return {"status": "published", "message_id": message_id}

@app.websocket("/v1/firehose")
async def firehose_stream(websocket: WebSocket):
    """
    WebSocket endpoint that streams indicators from Pub/Sub to authenticated clients.
    """
    await websocket.accept()
    
    # 1. Authenticate (Simple token check via query parameter for POC)
    api_key = websocket.query_params.get("api_key")
    if not await validate_api_key(api_key):
        await websocket.close(code=1008) # Policy Violation
        return

    # 2. Subscribe to Pub/Sub
    subscriber_client = pubsub_v1.SubscriberClient()
    # For POC, assume a subscription named 'global-firehose-sub' exists
    subscription_path = subscriber_client.subscription_path(PROJECT_ID, "global-firehose-sub")

    loop = asyncio.get_running_loop()

    def callback(message):
        data = message.data.decode("utf-8")
        try:
            # Schedule sending the message back to the websocket on the main loop
            asyncio.run_coroutine_threadsafe(websocket.send_text(data), loop)
            message.ack()
        except Exception as e:
            logger.error(f"WS send error: {e}")

    streaming_pull_future = subscriber_client.subscribe(subscription_path, callback=callback)
    
    try:
        while True:
            # Keep the connection alive and wait for client closure or errors
            # We don't expect messages FROM the client for this POC firehose
            data = await websocket.receive_text()
    except (WebSocketDisconnect, Exception):
        streaming_pull_future.cancel()
        logger.info("WebSocket disconnected")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
