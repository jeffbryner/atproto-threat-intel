# ISLF Threat-Intel (ATproto Edition) - Project Context

## Project Overview
This project is a Proof of Concept (POC) for a private, serverless threat intelligence network designed for ISLF members. It enables CISOs to sponsor automated machine readers and writers that share threat indicators (IoCs) in real-time.

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
  - **Protocol:** AT Protocol (simplified schema: `foundation.islf.intel.indicator`).

## Architecture & Data Flow
1. **Ingress:** A machine client sends an IoC and a Scoped API Key (Reader/Writer) to the Gateway.
2. **Validation:** The Gateway validates the API key hash against Firestore.
3. **Signing:** Validated records are stripped of sender information and signed using a master key in Cloud KMS.
4. **Broadcast:** Signed records are published to a Pub/Sub topic.
5. **Egress:** Clients connected via WebSocket receive signed JSON indicators in real-time.
6. **Anonymity:** All records are published under a fixed DID (`did:plc:islf-anonymous-member`).

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
- **Protocol Adherence:** Follow the `foundation.islf.intel.indicator` lexicon structure.

## Key Files
- `atproto-threat-intel-PRD.md`: The primary Product Requirements Document.
- `GEMINI.md`: This context file.
- `main.py` (Planned): The FastAPI entry point.
- `consumer_client.py` (Planned): Reference client for verifying signatures.
