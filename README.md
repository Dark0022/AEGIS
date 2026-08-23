AEGIS
AEGIS (Authenticated Evidence & Governance Integrity System) is a production-oriented platform for creating, signing, publishing, and independently verifying official communications.
It is designed around a simple trust model:
> **A notice should be publishable only when its identity, authorization, cryptographic provenance, content integrity, and credential status can be independently verified.**
What AEGIS does
AEGIS provides an end-to-end workflow for official notices:
An authorized publisher creates a notice.
The notice and source asset are stored using durable cloud-backed infrastructure.
The final asset is uploaded directly to Backblaze B2 using a short-lived presigned URL.
An isolated signing service performs the cryptographic signing operation.
The resulting asset is verified independently by AEGIS.
The notice is published only after successful verification.
Audit events are recorded in a hash-linked audit chain.
Public users can retrieve and verify published signed assets.
The current production architecture separates the signing service from the public/API layer so that the private issuer key is not exposed to the Vercel application.
Production architecture
```text
                    ┌──────────────────────┐
                    │      Web Frontend    │
                    │  Publisher / Verify  │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │      Vercel API      │
                    │ FastAPI / Python     │
                    └───────┬───────┬──────┘
                            │       │
                  PostgreSQL │       │ presigned upload
                            │       ▼
                            │  ┌──────────────┐
                            │  │ Backblaze B2 │
                            │  │ Asset Store  │
                            │  └──────┬───────┘
                            │         │
                            │         │ source asset
                            ▼         ▼
                    ┌──────────────────────┐
                    │   Render Signer      │
                    │ Isolated signing svc │
                    └──────────┬───────────┘
                               │
                               ▼
                    Signed / provenance asset
                               │
                               ▼
                    Independent verification
                               │
                               ▼
                         Publication
```
Current production services
Component	Role
Vercel	Public web application and API
Neon / PostgreSQL	Durable notice, publisher, credential, and audit state
Backblaze B2	Private object storage for source and published assets
Render	Isolated AEGIS signing service
C2PA / PKI	Cryptographic provenance and certificate trust
GitHub	Source control and deployment source
Core security properties
Isolated signing
Private issuer key material is kept in the isolated Render signing service rather than the public Vercel runtime.
The signer requires its certificate chain and signing artifacts to be present before signing can occur.
Cryptographic provenance
AEGIS creates signed assets using its PKI and provenance layer. Verification checks include:
signing credential trust
certificate validity
claim signature validity
content/data hash integrity
provenance validity
credential lifecycle state
A successfully published asset is therefore more than an uploaded file: it is an independently verifiable cryptographic artifact.
Durable audit trail
Notice mutations are recorded as audit events linked by hashes. The API returns an `audit_chain_valid` result with workflow mutations so the integrity of the audit chain can be checked.
Examples of workflow events include:
`CREATED`
`UPDATED`
`SUBMITTED_FOR_APPROVAL`
`APPROVED`
`PUBLICATION_AUTHORIZED`
`SIGNED`
`PUBLISHED`
Role-based workflow
The system distinguishes publisher and approval responsibilities.
Publication policy is derived from notice type. Current frontend behavior treats the following as direct-publication categories:
Emergency
Safety
General
General Announcement
Other notice types use an approval-required workflow.
Typical roles include:
`PUBLISHER`
`APPROVER`
`NOTICE_ADMIN`
Repository structure
```text
AEGIS/
├── api/
│   └── index.py
├── apps/
│   ├── api/
│   │   ├── config.py
│   │   ├── main.py
│   │   └── requirements.txt
│   └── web/
│       ├── index.html
│       ├── publisher.html
│       ├── publisher.js
│       ├── dashboard.html
│       ├── dashboard.js
│       ├── admin.html
│       └── admin.js
├── datasets/
│   └── synthetic/
├── packages/
│   ├── crypto/
│   ├── provenance/
│   ├── trust/
│   └── storage_b2.py
├── scripts/
├── signer_service/
│   └── app.py
├── pki/
├── render.yaml
├── vercel.json
├── pyproject.toml
├── requirements.txt
└── uv.lock
```
Important directories
`apps/api/`
FastAPI application exposed through the Vercel deployment.
The production API includes endpoints for:
```text
/health
/notices
/notices/{notice_id}
/notices/{notice_id}/submit
/notices/{notice_id}/approve
/notices/{notice_id}/publish
/notices/{notice_id}/asset-upload-url
/notices/{notice_id}/sign-publish
/notices/{notice_id}/audit
/public/notices/{notice_id}/asset
/publisher/login
/publisher/session/validate
/publisher/session/revoke
/admin/login
/admin/session/validate
/admin/session/revoke
/admin/audit
/credentials/{certificate_serial_number}
/credentials/{certificate_serial_number}/history
/credentials/{certificate_serial_number}/revoke
/verify
```
`apps/web/`
Browser interfaces for publishers, administrators, dashboards, and public verification.
The production frontend uses the same-origin API path:
```js
const API_BASE = "/api";
```
This allows the frontend to work under the Vercel production domain without pointing browser requests at a developer machine.
`packages/crypto/`
Cryptographic primitives, PKI handling, signing providers, key stores, hashing, signing, and verification.
`packages/provenance/`
C2PA asset creation, signing, verification, notice signing, and tamper-detection functionality.
`packages/trust/`
The trust and governance layer:
notice storage
publisher authentication
administrator authentication
credentials
PostgreSQL runtime
audit chain
verification decisions
workflow authorization
`signer_service/`
The isolated signing service deployed independently from the public API.
Production deployment
Vercel
The web/API application is deployed to Vercel.
Production URL:
```text
https://aegis-blush.vercel.app
```
API health check:
```text
https://aegis-blush.vercel.app/api/health
```
Render
The isolated signing service is deployed to Render.
Health check:
```text
https://aegis-signer.onrender.com/health
```
The Render service uses:
```yaml
services:
  - type: web
    name: aegis-signer
    runtime: python
    plan: free

    buildCommand: pip install uv && uv sync --frozen

    startCommand: uv run uvicorn signer_service.app:app --host 0.0.0.0 --port $PORT

    healthCheckPath: /health
```
Backblaze B2
The production asset bucket is private.
Browser uploads use short-lived presigned S3-compatible URLs. The production web origin is explicitly allowed by the bucket's S3-compatible CORS rules.
The bucket is intended to remain private; AEGIS controls access through signed URLs and API-mediated publication.
Environment variables
Secrets must never be committed to Git.
Typical production configuration includes variables such as:
```text
DATABASE_URL
B2_ENDPOINT
B2_BUCKET
B2_KEY_ID
B2_APPLICATION_KEY

AEGIS_ISSUER_KEY_PATH
AEGIS_ISSUER_KEY_PASSWORD
```
Additional application-specific settings may be required by the deployed configuration.
Keep all secret environment variables marked Sensitive in Vercel.
Private PKI key material must never be committed.
Public certificates may be committed when required for the trust chain.
Local development
Create and activate a virtual environment:
```bash
python -m venv .venv
```
Windows:
```cmd
.venv\Scripts\activate
```
Install dependencies:
```bash
pip install -r requirements.txt
```
If using `uv`:
```bash
uv sync
```
Run the API locally:
```bash
uv run uvicorn apps.api.main:app --reload
```
The exact local configuration depends on the selected storage backend and required development credentials.
Running tests
Run the full test suite with:
```bash
pytest
```
Targeted tests can be run by package, for example:
```bash
pytest packages/crypto
pytest packages/provenance
pytest packages/trust
pytest apps/api
```
Security rules
Never commit
Do not commit:
```text
.env
.env.*
AEGIS-SECRETS/
*.key
*.pem
*.p12
*.pfx
*.jks
```
Private PKI JSON artifacts and local secret stores must also remain excluded.
Public certificates
The repository may contain public trust-chain certificates when they are explicitly required by the deployed verification/signing workflow.
Public certificates do not contain private key material.
Secret rotation
If a secret is exposed:
Revoke the compromised credential.
Generate a replacement.
Update the production secret store.
Redeploy affected services.
Verify the production path.
Remove accidental local copies.
API workflow
Direct publication
For a direct-publication notice:
```text
Create Draft
   ↓
Upload Source Asset
   ↓
Request Sign/Publish
   ↓
Isolated Render Signer
   ↓
Independent Verification
   ↓
PUBLISHED
```
Approval-required publication
For an approval-required notice:
```text
Create Draft
   ↓
Submit
   ↓
READY_FOR_APPROVAL
   ↓
Approve
   ↓
APPROVED
   ↓
Upload Asset
   ↓
Sign
   ↓
Verify
   ↓
PUBLISHED
```
The frontend already reflects these workflow rules when deciding whether Save, Submit, Approve, and Sign & Publish actions are available.
Verification
Published assets can be retrieved through the public notice asset endpoint and checked by the AEGIS verification engine.
Verification considers:
```text
issuer trust
signature validity
content integrity
provenance validity
credential status
```
A trusted result requires the relevant trust and integrity checks to succeed.
Operational principles
AEGIS is intentionally designed so that:
source assets are stored separately from application state
private signing keys stay isolated
publishing requires cryptographic verification
audit history is retained
production secrets stay outside Git
public verification does not require access to private signing infrastructure
Current production milestone
The current deployment has been validated through the complete production path:
```text
Browser
  → Vercel API
  → PostgreSQL
  → Backblaze B2
  → Render isolated signer
  → C2PA signing
  → AEGIS verification
  → publication
```
The production publisher UI has successfully completed a real browser upload, signing, verification, and publication flow.
Roadmap
Planned/next workflow improvements include:
audited notice withdrawal
archived/withdrawn operational views
cleaner administrative lifecycle controls
production-domain configuration
further production observability
additional automated end-to-end deployment checks
License
See `LICENSE`.
Contributing
See `CONTRIBUTING.md`.
