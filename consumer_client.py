import json
import logging
import asyncio
import websockets
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
GATEWAY_URL = "ws://localhost:8000/v1/firehose"
API_KEY = "test-api-key-123" # Use a key that exists in your Firestore

# Placeholder for the ISLF Public Key (In a real app, this would be fetched or embedded)
# For POC, you can generate one or use a mock.
ISLF_PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE... (Replace with actual PEM)
-----END PUBLIC KEY-----"""

def verify_signature(public_key_pem, message_json):
    """
    Verifies the signature of a message using the ISLF Public Key.
    """
    try:
        data = json.loads(message_json)
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
        public_key.verify(
            signature,
            payload,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except Exception as e:
        logger.error(f"Signature verification failed: {e}")
        return False

async def listen_to_firehose():
    uri = f"{GATEWAY_URL}?api_key={API_KEY}"
    try:
        async with websockets.connect(uri) as websocket:
            logger.info(f"Connected to firehose at {GATEWAY_URL}")
            while True:
                message = await websocket.recv()
                logger.info(f"Received message: {message}")
                
                if verify_signature(ISLF_PUBLIC_KEY_PEM, message):
                    logger.info("✅ Signature Verified!")
                else:
                    logger.warning("❌ Signature Verification FAILED!")
                    
    except websockets.exceptions.ConnectionClosed:
        logger.info("Connection to firehose closed")
    except Exception as e:
        logger.error(f"Error: {e}")

if __name__ == "__main__":
    asyncio.run(listen_to_firehose())
