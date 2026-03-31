import json
import logging
import asyncio
import websockets
import hashlib
import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
GATEWAY_WS_URL = "ws://localhost:8000/v1/firehose"
GATEWAY_HTTP_URL = "http://localhost:8000"
CONSUMER_API_KEY = os.getenv(
    "CONSUMER_API_KEY"
)  # Use a key generated via the dashboard


async def get_public_key():
    """Fetches the Public Key from the gateway."""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{GATEWAY_HTTP_URL}/v1/public-key")
            if response.status_code == 200:
                data = response.json()
                if "pem" in data:
                    return data["pem"].encode("utf-8")
            logger.error(f"Failed to fetch public key: {response.text}")
    except Exception as e:
        logger.error(f"Error fetching public key: {e}")
    return None


async def fetch_history(limit=10, cursor=None):
    """Fetches historical indicators from the gateway."""
    params = {"limit": limit}
    if cursor:
        params["cursor"] = cursor

    headers = {"X-API-Key": CONSUMER_API_KEY}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{GATEWAY_HTTP_URL}/v1/indicators", params=params, headers=headers
            )
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(
                    f"Failed to fetch history ({response.status_code}): {response.text}"
                )
    except Exception as e:
        logger.error(f"Error fetching history: {e}")
    return None


def verify_signature(public_key_pem, data):
    """
    Verifies the signature of a message using the Public Key.
    'data' can be a JSON string or a dictionary.
    """
    if not public_key_pem:
        logger.warning("No public key available. Cannot verify signature.")
        return False

    try:
        if isinstance(data, str):
            data = json.loads(data)

        record = data["record"]
        signature_hex = data["signature"]

        # Canonicalize the record for verification (match the gateway's sorting)
        payload = json.dumps(record, sort_keys=True).encode("utf-8")
        signature = bytes.fromhex(signature_hex)

        if signature == b"unsigned-poc-signature":
            logger.warning("Received unsigned POC signature. Skipping verification.")
            return True

        public_key = serialization.load_pem_public_key(public_key_pem)

        # Verify the EC signature
        public_key.verify(signature, payload, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception as e:
        logger.error(f"Signature verification failed: {e}")
        return False


async def listen_to_firehose(public_key_pem):
    """Connects to the real-time firehose."""
    uri = f"{GATEWAY_WS_URL}?api_key={CONSUMER_API_KEY}"
    try:
        async with websockets.connect(uri) as websocket:
            logger.info(f"Connected to firehose at {GATEWAY_WS_URL}")
            while True:
                message = await websocket.recv()
                logger.info(f"Received message: {message}")

                if verify_signature(public_key_pem, message):
                    logger.info("✅ Signature Verified!")
                else:
                    logger.warning("❌ Signature Verification FAILED!")

    except websockets.exceptions.ConnectionClosed:
        logger.info("Connection to firehose closed")
    except Exception as e:
        logger.error(f"Error: {e}")


async def main():
    # 1. Fetch Public Key
    public_key_pem = await get_public_key()
    if not public_key_pem:
        logger.error("Critical: Could not fetch public key. Exiting.")
        return

    # 2. Sync History (ATproto style "catch up")
    logger.info("--- Syncing Historical Feed ---")
    history = await fetch_history(limit=5)
    if history and history.get("indicators"):
        # Process oldest to newest
        for entry in reversed(history["indicators"]):
            if verify_signature(public_key_pem, entry):
                rec = entry["record"]
                logger.info(
                    f"Verified History: [{rec['type']}] {rec['indicator']} - {rec['createdAt']}"
                )
            else:
                logger.warning(
                    f"Verification FAILED for history item: {entry['record']['indicator']}"
                )

    # 3. Listen to Firehose
    logger.info("--- Switching to Real-time Firehose ---")
    await listen_to_firehose(public_key_pem)


if __name__ == "__main__":
    asyncio.run(main())
