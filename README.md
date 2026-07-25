# Chameleon Key Vault

The Key Vault's source (this repo is `chameleon-vault` on GitHub) -- one
of three services a
[chameleon-installer](https://github.com/BrechtVanBuggenhout/chameleon-installer)
BYOC deployment runs (alongside `chameleon-pii-ingestor` and
`chameleon-console`). Most customers don't need this repo at all:
`bootstrap.sh` pulls Chameleon's pre-built image by default. Build from
here yourself only if you want to run entirely independent of
Chameleon's own container registry (see `chameleon-installer`'s
`scripts/build-own-images.sh`). This is also the actual crypto-shredding
implementation, published openly since auditability is part of the
trust story for a product whose whole pitch is provable deletion.

**Centralized Key Management Service (KMS) and cryptographic engine for Project Chameleon.**

Handles deterministic AES-256 user-level encryption, decryptions, and instantaneous data shredding.

## What Is This?

Instead of physically deleting user data from immutable databases, the Chameleon Key Vault manages encryption keys. When a user opts out, their encryption key is permanently destroyed, rendering all downstream copies of their data cryptographically unrecoverable—**mathematical erasure**.

This Node.js/Fastify microservice acts as the security gatekeeper for user PII across Project Chameleon's enterprise data ecosystem.

## Core Capabilities

- **Deterministic AES-256 Encryption:** Protects user PII at ingestion while retaining database functionality for joins, aggregations, and analytics.
- **Key Lifecycle Management:** Dynamically provisions and maps Data Encryption Keys (DEKs) to specific User IDs.
- **Instant Crypto-Shredding:** Securely destroys user keys upon request, rendering all downstream data permanently unrecoverable.
- **GCP Integration:** Seamless integration with Cloud KMS, Firestore, and audit logging via Cloud Logging.
- **Deterministic Guarantees:** Same plaintext + userId + key = same ciphertext, enabling reproducible audits and efficient database operations.

## Tech Stack

| Component | Technology |
|-----------|------------|
| **Runtime** | Node.js 20 LTS |
| **Framework** | Fastify (lightweight, high-performance) |
| **Cryptography** | Node.js built-in `crypto` (AES-256-GCM) |
| **Key Storage** | Google Cloud Firestore |
| **Key Rotation** | Google Cloud KMS |
| **Metadata** | Secret Manager |
| **Logging** | Pino + Cloud Logging |
| **Testing** | Jest + Supertest |

## Quick Start

### Prerequisites
- Node.js 20+ and npm 10+
- GCP projects configured (`your-gcp-project-id`, `your-gcp-project-id`)
- Service account with Firestore, KMS, and Secret Manager permissions

### Get Running (5 minutes)

```bash
# 1. Install dependencies
npm install

# 2. Configure environment
cp .env.example .env
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account-key.json

# 3. Start development server
npm run dev

# 4. Verify health
curl http://localhost:8080/health
```

See [CLAUDE.md](CLAUDE.md) for detailed setup and development guide.

## Endpoints (Phase 2)

### Health
- `GET /health` – Service status
- `GET /ready` – Readiness probe

### Key Management (In Development)
- `POST /key/generate` – Create encryption key for user
- `GET /key-status/:userId` – Query key lifecycle status
- `DELETE /key/shred` – Destroy user key (mathematical erasure)

### Encryption/Decryption (In Development)
- `POST /encrypt` – Encrypt PII with user's DEK
- `POST /decrypt` – Decrypt ciphertext back to plaintext

## Project Roadmap

This repo is **Phase 2** of Project Chameleon (the cryptographic backend):

| Phase | Status | Component |
|-------|--------|-----------|
| **Phase 1** | ✅ Complete | [GCP Infrastructure](../chameleon-infra-gcp) – Firestore, BigQuery, Cloud KMS, audit logging |
| **Phase 2a** | ✅ Complete | **Crypto Core** – Deterministic AES-256, Firestore registry, Cloud KMS integration |
| **Phase 2b** | ✅ Complete | **API Endpoints** – Encryption, decryption, key generation, shredding |
| **Phase 2c** | ✅ Complete | **Integration Tests** – End-to-end Milestone 2 verification |
| **Phase 2d** | ✅ Complete | **Observability** – Structured logging + Cloud Logging export |
| **Phase 2e** | ✅ In Progress | **Deployment & CI/CD** – Docker verification, GitHub Actions, Cloud Run |
| **Phase 3** | ✅ Complete | **Lineage Engine** – Track encrypted data through Reverse ETL destinations |
| **Phase 4** | ✅ Complete | **Certificate of Destruction** – Cryptographic proof of erasure |
| **Phase 5** | ✅ 5.1 Complete | **Janitor Orchestration** – SaaS wipes and DLQ tracking |

## Infrastructure Reference

All GCP infrastructure is managed in a separate repository using Terraform. See [GCP_INFRASTRUCTURE.md](../chameleon-infra-gcp/GCP_INFRASTRUCTURE.md) for:

- **Firestore:** Key registry with CMEK encryption
- **BigQuery:** Data warehouse with encrypted staging layer
- **Cloud KMS:** Key management with 90-day rotation policy
- **Cloud Storage:** Landing zone + audit log buckets with retention locks
- **Cloud Logging:** Audit trail of all data access and administrative actions
- **IAM:** Service accounts with least-privilege access controls

**Environment Separation:**
- **Dev:** `your-gcp-project-id` – Testing and experimentation
- **Prod:** `your-gcp-project-id` – Live key vault and data pipeline

## Testing

```bash
# Run all tests
npm test

# Watch mode during development
npm test:watch

# Coverage report
npm run test:coverage
```

## Development

```bash
# Start dev server (auto-reloads on changes)
npm run dev

# Type checking
npm run type-check

# Linting
npm run lint
npm run lint:fix

# Code formatting
npm run format
```

## Deployment

Deployment is owned by GitHub Actions and uses Workload Identity Federation.
Do not use JSON service account keys for this repo.

Required GitHub repository or environment variables:

| Variable | Source |
|----------|--------|
| `GCP_WORKLOAD_IDENTITY_PROVIDER` | `terraform output workload_identity_provider_name` |
| `GCP_DEPLOY_SERVICE_ACCOUNT` | `terraform output service_account_key_vault_deployer_email` |
| `KEY_VAULT_ARTIFACT_REPOSITORY_URL` | `terraform output key_vault_artifact_repository_url` |
| `KEY_VAULT_CLOUD_RUN_SERVICE_NAME` | `terraform output key_vault_cloud_run_service_name` |
| `KEY_VAULT_CLOUD_RUN_SERVICE_URI` | `terraform output key_vault_cloud_run_service_uri` |

Dev and prod deployment variables have been added in GitHub Actions. The workflows still validate them at runtime so missing environment-scoped values fail early.

If `terraform output workload_identity_provider_name` returns `null`, the infra repo has not enabled/applied Workload Identity Federation for the active environment yet. The four non-WIF variables can be configured first, but deploys will remain blocked until `GCP_WORKLOAD_IDENTITY_PROVIDER` is available.

```bash
# Local container build check
docker build -t chameleon-key-vault:local .
```

Dev deploys run from `.github/workflows/deploy-dev.yml` on pushes to `main` or manual dispatch.

Prod deploys are manual only through `.github/workflows/deploy-prod.yml`, require the `prod` GitHub environment approval gate, and require the workflow confirmation that prod Terraform has already been planned and applied from the prod backend/workspace with `prod.tfvars`.

Container vulnerability scanning runs in CI and prod deploys. It currently reports `HIGH` and `CRITICAL` findings without failing the workflow until the failure threshold is decided.

Cloud Run runtime environment variables are provided by Terraform:

```text
NODE_ENV
GCP_PROJECT_ID
FIRESTORE_DATABASE_ID
FIRESTORE_COLLECTION
CLOUD_KMS_PROJECT_ID
CLOUD_KMS_REGION
CLOUD_KMS_KEY_RING
CLOUD_KMS_KEY_NAME
SECRET_MANAGER_PROJECT_ID
CMEK_METADATA_SECRET_NAME
LOG_PROJECT_ID
LOG_LEVEL
```

Cloud Run injects `PORT`; the service defaults to `8080` when it is not set.

See [INFRA_ARCHITECTURE_TODO.md](INFRA_ARCHITECTURE_TODO.md) for Terraform handoff items needed before Cloud Run deployment is fully wired.

## Security

- **At Rest:** All keys encrypted with Cloud KMS (CMEK) before storage
- **In Transit:** TLS 1.2+ (enforced by Cloud Run)
- **Audit:** All key operations logged to Cloud Logging + archived to GCS with retention locks
- **Access:** Service accounts follow least-privilege principle per GCP IAM best practices

## Documentation

- [CLAUDE.md](CLAUDE.md) – Development setup and codebase tour
- [API_SPECIFICATION.md](API_SPECIFICATION.md) – Full endpoint documentation (TBD)
- [ARCHITECTURE.md](ARCHITECTURE.md) – Design decisions and data flow (TBD)
- [INFRA_ARCHITECTURE_TODO.md](INFRA_ARCHITECTURE_TODO.md) – Terraform handoff items for deployment
- [../chameleon-infra-gcp/GCP_INFRASTRUCTURE.md](../chameleon-infra-gcp/GCP_INFRASTRUCTURE.md) – Infrastructure details

## Contributing

1. Create a feature branch from `main`
2. Implement changes + add tests
3. Ensure `npm run lint` and `npm test` pass
4. Submit PR with description of changes
5. Code review required before merge

## License

MIT
