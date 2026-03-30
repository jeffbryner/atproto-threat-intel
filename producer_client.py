import json
import logging
import httpx
import sys
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
GATEWAY_URL = "http://localhost:8000/v1/submit"
PRODUCER_API_KEY = os.getenv("PRODUCER_API_KEY")  # Must match what's in Firestore


def submit_indicator(indicator_val, indicator_type, description):
    """
    Submits a threat indicator to the Gateway.
    """
    payload = {
        "indicator": indicator_val,
        "type": indicator_type,
        "description": description,
    }

    headers = {"X-API-Key": PRODUCER_API_KEY, "Content-Type": "application/json"}

    try:
        with httpx.Client() as client:
            response = client.post(GATEWAY_URL, json=payload, headers=headers)

            if response.status_code == 200:
                logger.info(f"✅ Submission successful: {response.json()}")
            else:
                logger.error(
                    f"❌ Submission failed ({response.status_code}): {response.text}"
                )

    except Exception as e:
        logger.error(f"Error connecting to Gateway: {e}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python producer_client.py <indicator> <type> [description]")
        sys.exit(1)

    indicator = sys.argv[1]
    ind_type = sys.argv[2]
    desc = sys.argv[3] if len(sys.argv) > 3 else "No description provided"

    submit_indicator(indicator, ind_type, desc)
