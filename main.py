import json
import logging
import os
import hashlib
import asyncio
import secrets
from datetime import datetime, timezone
from typing import Optional, List

from fastapi import (
    FastAPI,
    HTTPException,
    Security,
    WebSocket,
    WebSocketDisconnect,
    Request,
    Form,
)
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import APIKeyHeader
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel, Field
from google.cloud import firestore, kms, pubsub_v1
from google.api_core import exceptions
from authlib.integrations.starlette_client import OAuth, OAuthError
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Threat-Intel Gateway")

# Configuration (In a real app, use pydantic-settings or env vars)
PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT", "prj-atproto-threat-intel")
FIRESTORE_COLLECTION = "sponsored_keys"
PUBSUB_TOPIC = "threat-intel-firehose"
# Expected: projects/*/locations/*/keyRings/*/cryptoKeys/*/cryptoKeyVersions/*
KMS_KEY_NAME = os.getenv("KMS_KEY_NAME")
logger.info(f"Using KMS Key: {KMS_KEY_NAME}")

# Slack OIDC Configuration
SLACK_CLIENT_ID = os.getenv("SLACK_CLIENT_ID")
SLACK_CLIENT_SECRET = os.getenv("SLACK_CLIENT_SECRET")
SLACK_WORKSPACE_ID = os.getenv("SLACK_WORKSPACE_ID")  # Optional: restricted workspace
SESSION_SECRET = os.getenv("SESSION_SECRET", secrets.token_urlsafe(32))

# Initialize OAuth and Session Middleware
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET)
oauth = OAuth()
oauth.register(
    name="slack",
    client_id=SLACK_CLIENT_ID,
    client_secret=SLACK_CLIENT_SECRET,
    server_metadata_url="https://slack.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid profile email"},
)

# Template Setup
templates = Jinja2Templates(directory="templates")

# Initialize GCP Clients
db = firestore.Client(project=PROJECT_ID)
publisher = pubsub_v1.PublisherClient()
kms_client = kms.KeyManagementServiceClient()

# Security Header
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


class ThreatIndicator(BaseModel):
    indicator: str
    type: str  # ipv4, url, hash, etc.
    description: Optional[str] = None
    via: str = "did:plc:slack-anonymous-member"
    createdAt: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


async def validate_api_key(api_key: str, required_scope: Optional[str] = None) -> bool:
    """Validates the SHA-256 hash of the API key against Firestore and checks scope."""
    if not api_key:
        return False

    key_hash = hashlib.sha256(api_key.encode()).hexdigest()

    try:
        # Check Firestore for a document where the ID is the hash of the key
        doc_ref = db.collection(FIRESTORE_COLLECTION).document(key_hash)
        doc = doc_ref.get()
        if not doc.exists:
            return False

        key_data = doc.to_dict()
        if required_scope and required_scope not in key_data.get("scopes", []):
            logger.warning(
                f"Key {key_hash[:8]}... missing required scope: {required_scope}"
            )
            return False

        return True
    except exceptions.GoogleAPICallError as e:
        logger.error(f"Firestore error: {e}")
        return False


@app.post("/v1/submit")
async def submit_indicator(
    indicator: ThreatIndicator, api_key: str = Security(api_key_header)
):
    """
    Validates the API key (writer scope), signs the indicator with KMS, and publishes to Pub/Sub.
    """
    if not await validate_api_key(api_key, required_scope="writer"):
        raise HTTPException(status_code=403, detail="Invalid or unauthorized API Key")

    # 1. Prepare the record (Anonymize/Format)
    record = indicator.model_dump()
    record["via"] = "did:plc:slack-anonymous-member"  # Ensure anonymity

    payload = json.dumps(record, sort_keys=True).encode("utf-8")

    # 2. Sign with KMS
    if not KMS_KEY_NAME:
        logger.warning("KMS_KEY_NAME not configured, skipping signature for POC")
        signature = b"unsigned-poc-signature"
    else:
        try:
            logger.info(f"Signing payload with KMS key: {KMS_KEY_NAME}")
            response = kms_client.asymmetric_sign(
                request={
                    "name": KMS_KEY_NAME,
                    "digest": {"sha256": hashlib.sha256(payload).digest()},
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
        "alg": "EC_SIGN_P256_SHA256",
    }

    # 4. Broadcast to Pub/Sub
    topic_path = publisher.topic_path(PROJECT_ID, PUBSUB_TOPIC)
    future = publisher.publish(topic_path, json.dumps(signed_message).encode("utf-8"))
    message_id = future.result()

    return {"status": "published", "message_id": message_id}


@app.websocket("/v1/firehose")
async def firehose_stream(websocket: WebSocket):
    """
    WebSocket endpoint that streams indicators from Pub/Sub to authenticated clients (reader scope).
    """
    await websocket.accept()

    # 1. Authenticate (Simple token check via query parameter for POC)
    api_key = websocket.query_params.get("api_key")
    if not await validate_api_key(api_key, required_scope="reader"):
        await websocket.close(code=1008)  # Policy Violation
        return

    # 2. Subscribe to Pub/Sub
    subscriber_client = pubsub_v1.SubscriberClient()
    # For POC, assume a subscription named 'global-firehose-sub' exists
    subscription_path = subscriber_client.subscription_path(
        PROJECT_ID, "global-firehose-sub"
    )

    loop = asyncio.get_running_loop()

    def callback(message):
        data = message.data.decode("utf-8")
        try:
            # Schedule sending the message back to the websocket on the main loop
            asyncio.run_coroutine_threadsafe(websocket.send_text(data), loop)
            message.ack()
        except Exception as e:
            logger.error(f"WS send error: {e}")

    streaming_pull_future = subscriber_client.subscribe(
        subscription_path, callback=callback
    )

    try:
        while True:
            # Keep the connection alive and wait for client closure or errors
            # We don't expect messages FROM the client for this POC firehose
            data = await websocket.receive_text()
    except (WebSocketDisconnect, Exception):
        streaming_pull_future.cancel()
        logger.info("WebSocket disconnected")


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    user = request.session.get("user")
    keys = []
    if user:
        # Fetch user's keys from Firestore
        docs = (
            db.collection(FIRESTORE_COLLECTION)
            .where("sponsor_id", "==", user["sub"])
            .stream()
        )
        for doc in docs:
            d = doc.to_dict()
            d["id"] = doc.id  # The hash
            keys.append(d)

    return templates.TemplateResponse(
        request=request, name="index.html", context={"user": user, "keys": keys}
    )


@app.get("/v1/auth/login")
async def login(request: Request):
    redirect_uri = request.url_for("auth_callback")
    return await oauth.slack.authorize_redirect(request, str(redirect_uri))


@app.get("/v1/auth/callback")
async def auth_callback(request: Request):
    try:
        token = await oauth.slack.authorize_access_token(request)
        user = token.get("userinfo")
        if user:
            # Check workspace restriction if configured
            # Slack userinfo usually contains 'https://slack.com/team_id' in OIDC
            team_id = user.get("https://slack.com/team_id")
            if SLACK_WORKSPACE_ID and team_id != SLACK_WORKSPACE_ID:
                logger.warning(f"Unauthorized workspace login attempt: {team_id}")
                return HTMLResponse("Unauthorized Slack Workspace", status_code=403)

            request.session["user"] = dict(user)
    except OAuthError as e:
        logger.error(f"OAuth error: {e}")
        return HTMLResponse("Authentication failed", status_code=400)
    return RedirectResponse(url="/")


@app.get("/v1/auth/logout")
async def logout(request: Request):
    request.session.pop("user", None)
    return RedirectResponse(url="/")


@app.post("/v1/keys")
async def create_key(
    request: Request, scope: str = Form(...), description: str = Form("No description")
):
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # 1. Generate a random API key
    raw_key = f"ti_{secrets.token_urlsafe(24)}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

    # 2. Store in Firestore
    db.collection(FIRESTORE_COLLECTION).document(key_hash).set(
        {
            "sponsor_id": user["sub"],
            "sponsor_name": user.get("name"),
            "scopes": [scope],
            "description": description,
            "createdAt": firestore.SERVER_TIMESTAMP,
        }
    )

    # 3. Flash the raw key to the user (ONLY ONCE)
    request.session["new_key"] = raw_key
    return RedirectResponse(url="/", status_code=303)


@app.post("/v1/keys/revoke")
async def revoke_key(request: Request, key_id: str = Form(...)):
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # Ensure the user owns the key before deleting
    doc_ref = db.collection(FIRESTORE_COLLECTION).document(key_id)
    doc = doc_ref.get()
    if doc.exists and doc.to_dict().get("sponsor_id") == user["sub"]:
        doc_ref.delete()
        logger.info(f"Revoked key {key_id[:8]}...")

    return RedirectResponse(url="/", status_code=303)


@app.get("/v1/public-key")
async def get_public_key():
    """Returns the Public Key in PEM format from Cloud KMS."""
    if not KMS_KEY_NAME:
        return {"error": "KMS_KEY_NAME not configured"}

    try:
        response = kms_client.get_public_key(name=KMS_KEY_NAME)
        return {"pem": response.pem}
    except Exception as e:
        logger.error(f"Failed to fetch public key from KMS: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch public key")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
