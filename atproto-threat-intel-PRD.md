This PRD is designed to be fed into a coding assistant (like Gemini-cli or Cursor) to generate a functional Proof of Concept. It focuses on the **"Sponsorship"** and **"Anonymization"** requirements we've established.

---

# PRD: Slack Decentralized Threat Firehose (POC)

## 1. Executive Summary
**Project Name:** Slack Community Threat-Intel (ATproto Edition)  
**Objective:** Create a private, serverless threat intelligence network for members.  
**Core Value:** Allow CISOs to "sponsor" automated machine readers/writers that share threat indicators (IoCs) in real-time. All data is cryptographically signed by the Root Key to ensure authenticity while maintaining member anonymity.

---

## 2. Personas & User Stories
* **The Sponsor (CISO):** A member who uses Slack to manage the "Machine Keys" for their company.
* **The Machine (Reader/Writer):** A security tool (SIEM/EDR/etc) that uses an API Key to either push or pull threat data.
* **The Global Network:** The aggregated, real-time stream of all "Verified" threats.

---

## 3. Technical Requirements
Google Cloud, python and serverless wherever possible.
Python will always use uv for virtual environment management.


### A. Identity & Auth (The Gatekeeper)
* **Identity Provider:** Slack OIDC.
* **Verification:** Users must be members of a specific Slack Workspace ID and Channel ID.
* **Sponsorship Model:** The Web UI allows a logged-in Slack user to generate **Scoped API Keys** (Reader or Writer).
* **Storage:** Firestore stores the SHA-256 hashes of these keys mapped to the Sponsor’s Slack ID.

### B. Data Protocol (The Lexicon)
* **Protocol:** AT Protocol (simplified for POC).
* **Schema:** `foundation.slack.intel.indicator`
* **Fields:** `indicator` (string), `type` (ipv4/url/hash), `description` (string), `via` (DID), `createdAt` (ISO8601).
* **Anonymity:** Every record is published with the fixed DID `did:plc:slack-anonymous-member`.

### C. The Serverless Stack (GCP)
* **API/Websocket:** Cloud Run (Python/FastAPI).
* **Message Bus:** Cloud Pub/Sub.
* **Cryptography:** Cloud KMS (Asymmetric Signing - `EC_SIGN_P256_SHA256`).
* **Database:** Firestore.

---

## 4. System Architecture
1.  **Ingress:** A machine client sends an IoC + API Key to the Cloud Run API.
2.  **Validation:** Cloud Run checks the key against Firestore.
3.  **Signing:** Cloud Run strips the sender's info, constructs the ATproto record, and signs it using the **Cloud KMS Master Key**.
4.  **Broadcast:** The signed record is published to Pub/Sub.
5.  **Egress:** Connected WebSocket clients (Readers) receive the signed JSON immediately.

---

## 5. Success Metrics for POC
1.  **Verification:** A client can only connect if they provide a valid "Sponsored" API key.
2.  **Authenticity:** A client can verify the signature of an incoming threat using only the Public Key.
3.  **Latency:** Indicators travel from "Writer" to "Reader" in < 500ms.
4.  **Anonymity:** The public firehose stream contains zero references to the original Slack User or Company.

---

## 6. Implementation Checklist (Phase 1)
Use existing project: prj-atproto-threat-intel
* [ ] Set up Google Cloud Project with KMS, Pub/Sub, and Firestore.
* [ ] Create a Slack App manifest for OIDC.
* [ ] Implement the `Gateway` service (FastAPI) with two endpoints:
    * `POST /v1/submit`: Validates key, signs with KMS, pushes to Pub/Sub.
    * `WS /v1/firehose`: Validates key, streams from Pub/Sub.
* [ ] Write a `consumer_client.py` script that verifies signatures using `cryptography` library.

---
