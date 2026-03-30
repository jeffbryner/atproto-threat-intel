# Slack Community Threat-Intel (ATproto Edition) - Project Context

## Project Overview
This project is a Proof of Concept (POC) for a private, serverless threat intelligence network designed for slack members. It enables CISOs to sponsor automated machine readers and writers that share threat indicators (IoCs) in real-time.

- **Objective:** Secure, anonymous, and authentic threat intelligence sharing.
- **Core Technology Stack:**
  - **Language:** Python 3.12+
  - **Framework:** FastAPI
  - **Package Management:** `uv`
  - **Infrastructure (GCP):**
    - **Cloud Run:** API and WebSocket Gateway.
    - **Cloud KMS:** Asymmetric signing of threat records.
    - **Cloud Pub/Sub:** Real-time message bus.
    - **Firestore:** Storage for API keys and sponsorship mappings.
  - **Protocol:** AT Protocol (simplified schema: `foundation.slack.intel.indicator`).

## Architecture & Data Flow
1. **Ingress:** A machine client sends an IoC and a Scoped API Key (Reader/Writer) to the Gateway.
2. **Validation:** The Gateway validates the API key hash against Firestore.
3. **Signing:** Validated records are stripped of sender information and signed using a master key in Cloud KMS.
4. **Broadcast:** Signed records are published to a Pub/Sub topic.
5. **Egress:** Clients connected via WebSocket receive signed JSON indicators in real-time.
6. **Anonymity:** All records are published under a fixed DID (`did:plc:slack-anonymous-member`).

## Building and Running
The project uses `uv` for environment and dependency management.

- **Setup Environment:**
  ```bash
  uv venv
  source .venv/bin/activate
  ```
- **Install Dependencies:**
  ```bash
  uv pip install fastapi uvicorn google-cloud-kms google-cloud-pubsub google-cloud-firestore
  ```
- **Run the Gateway (Planned):**
  ```bash
  uv run uvicorn main:app --reload
  ```

## Development Conventions
- **Environment Management:** Always use `uv`.
- **Security:** Never log or expose API keys. Use SHA-256 hashing for key storage in Firestore.
- **Cloud First:** Design for serverless execution on Google Cloud Platform.
- **Protocol Adherence:** Follow the `foundation.slack.intel.indicator` lexicon structure.

## Key Files
- `atproto-threat-intel-PRD.md`: The primary Product Requirements Document.
- `GEMINI.md`: This context file.
- `main.py` (Planned): The FastAPI entry point.
- `consumer_client.py` (Planned): Reference client for verifying signatures.



## Step 1 Status
I have completed the initial build of the Slack Threat-Intel POC. The following components are now ready:

   - Gateway Service (main.py): A FastAPI application that validates API keys via Firestore, signs threat indicators with Google Cloud KMS, and
     broadcasts them through Pub/Sub.
   - Consumer Client (consumer_client.py): A WebSocket client that subscribes to the firehose and verifies the cryptographic signatures of incoming
     threat data.
   - Producer Client (producer_client.py): A utility to submit new threat indicators to the gateway.
   - Setup Utility (setup_poc.py): A script that provides step-by-step instructions for GCP resource creation and handles seeding Firestore with test API
     keys.

  Next Steps
   1. Configure GCP: Follow the instructions printed by python setup_poc.py.
   2. Seed Test Data: Run python setup_poc.py --seed to create a test API key in your Firestore instance.
   3. Launch the Gateway: Start the server with uv run uvicorn main:app --reload.
   4. Test the Flow: Run consumer_client.py in one terminal and producer_client.py in another to see real-time, verified threat intelligence in action.
                                                                                                                              
## Step 2 Status
I've completed the implementation of the next phase of the Slack Threat-Intel POC, transforming the gateway into a full sponsorship-driven platform.

  Key Enhancements

   1. Slack OIDC Identity & Auth:
       * Added /v1/auth/login and /v1/auth/callback endpoints using Authlib to allow slack members to authenticate with their Slack accounts.
       * Implemented session management using secure, signed cookies.
       * Created a slack_manifest.yaml for easy Slack App configuration.

   2. Sponsorship Dashboard:
       * Built a modern, responsive Web UI (served at /) where authenticated Slack users can manage their "machine keys."
       * Users can generate new keys for specific scopes (Reader or Writer) and revoke them when they are no longer needed.
       * The cleartext API key is only displayed once upon generation for security.

   3. Scoped Authorization:
       * Refined the machine authentication system to enforce specific permissions:
           * Writer Scope: Required for POST /v1/submit to publish new threat indicators.
           * Reader Scope: Required for WS /v1/firehose to receive the real-time stream.
       * API keys are now stored in Firestore with mappings to the sponsoring Slack User ID and their assigned scope.

   4. KMS Public Key Distribution:
       * Added a GET /v1/public-key endpoint that serves the slack Public Key directly from Google Cloud KMS.
       * Updated consumer_client.py to automatically fetch this key, enabling seamless cryptographic signature verification without hardcoded keys.

  Getting Started with the New Features

   1. Create your Slack App:
       * Import the new slack_manifest.yaml into your Slack workspace.
       * Gather your SLACK_CLIENT_ID and SLACK_CLIENT_SECRET.

   2. Configure your environment:

   1     export SLACK_CLIENT_ID="your-id"
   2     export SLACK_CLIENT_SECRET="your-secret"
   3     export SLACK_WORKSPACE_ID="T..." # Optional: to restrict logins to your Slack Team
   4     export KMS_KEY_NAME="projects/.../cryptoKeyVersions/1"

   3. Launch the Gateway:
   1     uv run uvicorn main:app --reload

   4. Manage Keys: Navigate to http://localhost:8000 to log in via Slack and generate your first scoped machine keys.

   5. Test the Clients: Use your newly generated keys with producer_client.py and consumer_client.py to verify the end-to-end authenticated flow.                                                                                                                              