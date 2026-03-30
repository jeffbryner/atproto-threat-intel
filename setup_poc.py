import hashlib
import os
import logging
from google.cloud import firestore

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT", "prj-atproto-threat-intel")
FIRESTORE_COLLECTION = "sponsored_keys"
TEST_API_KEY = "test-api-key-123"

def seed_firestore():
    """Seeds Firestore with a test API key for the POC."""
    db = firestore.Client(project=PROJECT_ID)
    key_hash = hashlib.sha256(TEST_API_KEY.encode()).hexdigest()
    
    doc_ref = db.collection(FIRESTORE_COLLECTION).document(key_hash)
    doc_ref.set({
        "sponsor": "POC-User",
        "description": "Test key for POC development",
        "createdAt": firestore.SERVER_TIMESTAMP,
        "scopes": ["reader", "writer"]
    })
    
    logger.info(f"✅ Firestore seeded with test key hash: {key_hash}")
    logger.info(f"🔑 Your cleartext test API key is: {TEST_API_KEY}")

def print_gcp_instructions():
    """Prints instructions for setting up GCP resources."""
    instructions = f"""
--- GCP SETUP INSTRUCTIONS ---
1. Set your Project ID:
   export GOOGLE_CLOUD_PROJECT={PROJECT_ID}

2. Enable APIs:
   gcloud services enable firestore.googleapis.com kms.googleapis.com pubsub.googleapis.com run.googleapis.com

3. Create Firestore Database:
   gcloud firestore databases create --location=us-central1

4. Create Pub/Sub Topic and Subscription:
   gcloud pubsub topics create threat-intel-firehose
   gcloud pubsub subscriptions create global-firehose-sub --topic=threat-intel-firehose

5. Create KMS Key Ring and Asymmetric Key:
   gcloud kms keyrings create islf-intel-poc --location=us-central1
   gcloud kms keys create islf-root-key --location=us-central1 --keyring=islf-intel-poc --purpose=asymmetric-signing --default-algorithm=ec-sign-p256-sha256

6. Get the Key Name and export it:
   # Note the name of the key version 1
   export KMS_KEY_NAME="projects/{PROJECT_ID}/locations/us-central1/keyRings/islf-intel-poc/cryptoKeys/islf-root-key/cryptoKeyVersions/1"

7. Run the Gateway:
   uv run uvicorn main:app --reload
-------------------------------
    """
    print(instructions)

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--seed":
        try:
            seed_firestore()
        except Exception as e:
            logger.error(f"Failed to seed Firestore: {e}")
            logger.info("Make sure you have authenticated with: gcloud auth application-default login")
    
    print_gcp_instructions()
