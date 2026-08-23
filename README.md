# AEGIS

<p align="center">
  <strong>Authenticated Evidence & Governance Integrity System</strong>
</p>

<p align="center">
  <em>Cryptographically verifiable infrastructure for trusted official communications.</em>
</p>

<p align="center">

[![Production](https://img.shields.io/badge/production-live-success?style=for-the-badge)](https://aegis-blush.vercel.app)
[![API](https://img.shields.io/badge/API-FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://aegis-blush.vercel.app/api/health)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Neon-4169E1?style=for-the-badge&logo=postgresql&logoColor=white)](https://neon.tech/)
[![Storage](https://img.shields.io/badge/Storage-Backblaze%20B2-EF3B2D?style=for-the-badge)](https://www.backblaze.com/b2/cloud-storage.html)
[![Signer](https://img.shields.io/badge/Signer-Render-46E3B7?style=for-the-badge&logo=render&logoColor=black)](https://render.com/)
[![License](https://img.shields.io/badge/license-see%20LICENSE-lightgrey?style=for-the-badge)](LICENSE)

</p>

---

## Overview

**AEGIS** is a production-oriented platform for creating, authorizing, cryptographically signing, publishing, and independently verifying official communications.

The system is designed around one core principle:

> **An official communication should not be trusted merely because it exists online. Its identity, authorization, provenance, integrity, and signing credential should be independently verifiable.**

AEGIS combines:

- Role-based publication workflows
- PostgreSQL-backed durable state
- Private object storage
- Isolated cryptographic signing
- PKI-based trust
- C2PA provenance
- Cryptographic content integrity
- Hash-linked audit trails
- Independent verification

The result is an architecture where the **public application does not need access to the private signing key** in order to publish trusted communications.

---

# Architecture

```text
                         ┌──────────────────────────┐
                         │      AEGIS Web UI        │
                         │                          │
                         │ Publisher / Admin /     │
                         │ Verification Interfaces │
                         └────────────┬─────────────┘
                                      │
                                      ▼
                         ┌──────────────────────────┐
                         │       Vercel API         │
                         │        FastAPI            │
                         │                          │
                         │ Auth / Workflow / Trust │
                         └───────┬──────────┬───────┘
                                 │          │
                     PostgreSQL  │          │ Presigned upload
                                 │          │
                                 ▼          ▼
                      ┌────────────────┐  ┌────────────────┐
                      │ Neon PostgreSQL │  │  Backblaze B2  │
                      │                │  │                │
                      │ Notices        │  │ Source Assets  │
                      │ Publishers     │  │ Signed Assets  │
                      │ Credentials    │  │                │
                      │ Audit State    │  │ Private Bucket │
                      └────────────────┘  └───────┬────────┘
                                                   │
                                                   │ Source asset
                                                   ▼
                                      ┌────────────────────────┐
                                      │   Isolated Signer      │
                                      │        Render          │
                                      │                        │
                                      │ Private issuer key    │
                                      │ C2PA / PKI signing    │
                                      └────────────┬───────────┘
                                                   │
                                                   ▼
                                      ┌────────────────────────┐
                                      │ Independent AEGIS      │
                                      │ Verification Engine    │
                                      │                        │
                                      │ Signature              │
                                      │ Provenance             │
                                      │ Integrity              │
                                      │ Credential Status      │
                                      └────────────┬───────────┘
                                                   │
                                                   ▼
                                           ┌───────────────┐
                                           │   PUBLISHED   │
                                           └───────────────┘


Production
Web Application

https://aegis-blush.vercel.app

API Health

https://aegis-blush.vercel.app/api/health

Isolated Signing Service

https://aegis-signer.onrender.com/health

The production API currently reports:

{
  "status": "ok",
  "service": "aegis-verification-api",
  "environment": "production",
  "version": "0.7.0",
  "storage_backend": "postgres"
}

The isolated signing service reports:

{
  "status": "ok",
  "service": "aegis-signing-service"
}
Core Workflow
1. Create

An authorized publisher creates a notice.

PUBLISHER
    │
    ▼
Create Draft

The notice is stored in PostgreSQL and an audit event is created.

2. Determine Publication Policy

AEGIS assigns a publication policy based on notice type.

Current direct-publication categories include:

Emergency
Safety
General
General Announcement

Other categories require approval.

DIRECT
    │
    └──────► Publisher may proceed to signing

APPROVAL_REQUIRED
    │
    └──────► Approval required before signing
3. Upload

The browser requests a short-lived presigned upload URL from the API.

The asset is then uploaded directly to Backblaze B2.

Browser
   │
   │ request upload URL
   ▼
AEGIS API
   │
   │ presigned URL
   ▼
Browser ───────────────► Backblaze B2

The private B2 credentials never need to be placed in browser code.

4. Sign

AEGIS asks the isolated signing service to process the uploaded asset.

Vercel API
    │
    │ source asset
    ▼
Render Signer
    │
    │ private issuer key
    ▼
Signed C2PA Asset

The private issuer key remains outside the public application environment.

5. Verify

The signed asset is independently checked before publication.

AEGIS verifies:

✓ Signing credential trust
✓ Certificate validity
✓ Claim signature
✓ Content/data hash
✓ Provenance
✓ Credential lifecycle state
6. Publish

Only after successful verification is the notice committed as published.

Sign
  ↓
Verify
  ↓
Trusted
  ↓
PUBLISHED

The resulting notice contains the signed asset reference and cryptographic hash.

Approval Workflow

For communications that require approval:

DRAFT
  │
  ▼
READY_FOR_APPROVAL
  │
  ▼
APPROVED
  │
  ▼
SIGNING
  │
  ▼
VERIFICATION
  │
  ▼
PUBLISHED

This separates content creation from publication authorization.

Cryptographic Trust Model

AEGIS uses multiple layers of verification.

Issuer Trust

The signing certificate must be trusted through the configured AEGIS PKI trust chain.

Signature Integrity

The cryptographic signature must validate successfully.

Content Integrity

The signed data must match its expected cryptographic hash.

Provenance

The asset's C2PA provenance must validate.

Credential Lifecycle

The signing credential must be in an acceptable lifecycle state.

A successful verification therefore represents a combined trust decision rather than a single signature check.

Audit Trail

AEGIS maintains a hash-linked audit chain.

Example lifecycle:

CREATED
   │
   ▼
UPDATED
   │
   ▼
SUBMITTED_FOR_APPROVAL
   │
   ▼
APPROVED
   │
   ▼
PUBLICATION_AUTHORIZED
   │
   ▼
SIGNED
   │
   ▼
PUBLISHED

Each event links to the previous event through cryptographic hashes.

This allows AEGIS to detect tampering with the audit history.

The API reports whether the audit chain remains valid:

{
  "audit_chain_valid": true
}
Security Model

AEGIS deliberately separates sensitive responsibilities.

Public/API Layer

The Vercel application handles:

Authentication
Authorization
Notice workflow
PostgreSQL access
B2 upload orchestration
Verification
Publication state
Signing Layer

The Render service handles:

Private issuer key access
Cryptographic signing
Signing certificate chain
C2PA asset creation
Storage Layer

Backblaze B2 handles:

Source assets
Signed assets
Durable object storage
Database Layer

Neon/PostgreSQL handles:

Notices
Publishers
Credentials
Sessions
Audit state
Why the Signer Is Isolated

The signing key is one of the most sensitive assets in the system.

AEGIS therefore avoids putting the private issuer key directly into the public Vercel application.

Instead:

Public application
       │
       │ authenticated signing request
       ▼
Isolated signer
       │
       │ private key
       ▼
Cryptographic signature

This reduces the blast radius of a compromise in the public application layer.

Repository Structure
AEGIS/
│
├── api/
│   └── index.py
│
├── apps/
│   ├── api/
│   │   ├── config.py
│   │   ├── main.py
│   │   ├── requirements.txt
│   │   └── tests
│   │
│   └── web/
│       ├── index.html
│       ├── publisher.html
│       ├── publisher.js
│       ├── publisher.css
│       ├── dashboard.html
│       ├── dashboard.js
│       ├── dashboard.css
│       ├── admin.html
│       ├── admin.js
│       ├── admin.css
│       └── ...
│
├── datasets/
│   └── synthetic/
│
├── packages/
│   ├── crypto/
│   ├── provenance/
│   ├── trust/
│   └── storage_b2.py
│
├── pki/
│
├── scripts/
│
├── signer_service/
│   └── app.py
│
├── pyproject.toml
├── requirements.txt
├── render.yaml
├── vercel.json
├── uv.lock
├── LICENSE
└── README.md
Main Components
apps/api

The primary FastAPI application.

Responsibilities include:

Authentication
Authorization
Notice lifecycle
Publication workflow
B2 integration
Signing-service integration
Verification
Audit APIs
apps/web

Browser interfaces.

Publisher

Create, edit, submit, approve where permitted, upload assets, and publish notices.

Dashboard

Operational view of communications and trust information.

Admin

Administrative credential and audit operations.

Verification

Independent verification of signed assets.

packages/crypto

Cryptographic primitives and PKI functionality.

Includes:

Hashing
Signing
Verification
PKI handling
Key providers
Persistent key providers
Certificate stores
packages/provenance

C2PA and provenance functionality.

Includes:

C2PA asset creation
C2PA signing
C2PA verification
Notice signing
Tamper detection
packages/trust

Governance and trust infrastructure.

Includes:

Notice storage
Publisher authentication
Administrator authentication
Credentials
Trust decisions
PostgreSQL runtime
Audit chains
Verification state
signer_service

Isolated production signing service.

This service is intentionally deployed separately from the main Vercel API.

API

The production API currently exposes endpoints including:

GET  /health

POST /publisher/login
POST /publisher/session/validate
POST /publisher/session/revoke

GET  /notices
POST /notices
GET  /notices/{notice_id}
PUT  /notices/{notice_id}

POST /notices/{notice_id}/submit
POST /notices/{notice_id}/approve
POST /notices/{notice_id}/publish
POST /notices/{notice_id}/asset-upload-url
POST /notices/{notice_id}/sign-publish
GET  /notices/{notice_id}/audit

GET  /public/notices/{notice_id}/asset

POST /verify

POST /admin/login
POST /admin/session/validate
POST /admin/session/revoke
GET  /admin/audit

GET  /credentials/{certificate_serial_number}
GET  /credentials/{certificate_serial_number}/history
POST /credentials/{certificate_serial_number}/revoke
Environment Variables

Production secrets must never be committed to Git.

Typical production configuration includes:

DATABASE_URL

B2_ENDPOINT
B2_BUCKET
B2_KEY_ID
B2_APPLICATION_KEY

AEGIS_ISSUER_KEY_PATH
AEGIS_ISSUER_KEY_PASSWORD

Depending on deployment configuration, additional application variables may be required.

Secret Handling Rules

Keep production credentials in:

Vercel Environment Variables
Render Environment Variables
Local .env.local for development only

Production secrets should remain marked Sensitive.

Never place secrets in:

GitHub
README files
Frontend JavaScript
Screenshots
Public documentation
Issue comments
Commit messages
PKI

AEGIS uses a certificate hierarchy for signing trust.

Conceptually:

Root CA
  │
  ▼
Institution CA
  │
  ▼
Issuer Certificate
  │
  ▼
Signing Key

Public trust-chain certificates can be distributed with the application when required for verification.

Private keys must never be committed.

Local Development

Clone the repository:

git clone https://github.com/Dark0022/AEGIS.git
cd AEGIS

Create a virtual environment:

python -m venv .venv
Windows
.venv\Scripts\activate

Install dependencies:

pip install -r requirements.txt

Or with uv:

uv sync

Start the API:

uv run uvicorn apps.api.main:app --reload
Testing

Run the complete test suite:

pytest

Run focused suites:

pytest packages/crypto
pytest packages/provenance
pytest packages/trust
pytest apps/api

Useful checks before committing:

git diff --check
git status
Production Deployment
Vercel

The production frontend/API is deployed through Vercel.

vercel --prod

The production frontend uses a same-origin API:

const API_BASE = "/api";

This is important because the browser should communicate with:

https://aegis-blush.vercel.app/api

rather than a developer machine such as:

http://127.0.0.1:8000
Render

The isolated signer is deployed from render.yaml.

Typical startup:

uv run uvicorn signer_service.app:app \
  --host 0.0.0.0 \
  --port $PORT

Health endpoint:

/health
Backblaze B2

The production bucket is private.

Browser uploads use:

Short-lived presigned S3 upload URL
        ↓
Direct browser → B2 PUT

The bucket's S3-compatible CORS rules explicitly allow the production frontend origin for upload operations.

Production Verification

Before considering a deployment healthy, verify:

API
curl https://aegis-blush.vercel.app/api/health
Signer
curl https://aegis-signer.onrender.com/health
Git
git status
git log --oneline --decorate --max-count=5
Browser

Verify:

Publisher login
      ↓
Notice creation
      ↓
B2 asset upload
      ↓
Signer invocation
      ↓
C2PA signing
      ↓
Independent verification
      ↓
Publication
Production Security Checklist

Before sharing or deploying the repository:

 No private keys committed
 No .env secrets committed
 No database URLs committed
 No B2 application keys committed
 No signing passwords committed
 Production credentials stored as Sensitive environment variables
 B2 bucket remains private
 B2 CORS restricted to approved origins
 Signing service isolated
 Public certificate chain verified
 Audit chain verified
 Production health endpoints respond successfully
 End-to-end publish test completed
 Compromised credentials rotated if exposed
Team Development Model

The repository can be shared publicly for visibility and collaboration.

Remember:

Public repository access does not grant write access.

Team members can clone the repository without being collaborators.

Only people explicitly granted repository permissions should be able to push directly to the repository.

For safer collaboration, contributors should generally:

Fork
  ↓
Create branch
  ↓
Make changes
  ↓
Open Pull Request
  ↓
Review
  ↓
Merge

For a production security platform, branch protection and pull-request review are strongly recommended.

Current Status
Production
Vercel API                 ✅
Neon PostgreSQL            ✅
Backblaze B2               ✅
B2 CORS                    ✅
Render isolated signer     ✅
PKI trust chain            ✅
C2PA signing               ✅
C2PA verification          ✅
Audit chain                ✅
Publisher authentication   ✅
Approval workflow          ✅
Production browser upload  ✅
Production publish flow    ✅
Roadmap

Planned improvements include:

Notice Lifecycle
Audited WITHDRAWN status
Administrative archive/withdraw controls
Historical notice views
Better operational filtering
Security
Stronger production access controls
Additional credential rotation tooling
More deployment security checks
Expanded end-to-end security tests
Operations
Better monitoring
Deployment diagnostics
Health dashboards
More detailed audit inspection
Developer Experience
Improved documentation
Easier local bootstrap
Contributor guides
Automated CI checks
Philosophy

AEGIS is built around a distinction between:

Having a file
        ≠
Knowing who created it
        ≠
Knowing whether it was authorized
        ≠
Knowing whether it was modified
        ≠
Knowing whether the credential is trusted

AEGIS attempts to make those properties explicit and machine-verifiable.

The goal is not simply to publish content.

The goal is to publish content with evidence of authenticity.                                           
