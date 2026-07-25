# Chameleon Key Vault - API Specification

## Overview

This document describes the complete REST API for the Chameleon Key Vault service. All endpoints use JSON for request/response payloads.

**Base URL:** `http://localhost:3000` (development) | `https://key-vault.chameleon.example.com` (production)

**Authentication:** Service accounts use Application Default Credentials (ADC) from GCP

---

## Response Format

All responses follow this format:

```json
{
  "statusCode": 200,
  "data": {...},
  "timestamp": "2025-05-23T12:34:56.789Z",
  "error": null  // null if successful
}
```

Error responses:

```json
{
  "statusCode": 400,
  "error": "Error message",
  "errors": [
    {
      "field": "userId",
      "message": "Validation error detail"
    }
  ]
}
```

---

## Endpoints

### 1. Health Check

#### GET /health

Verify service is running and responding.

**Response:**
```json
{
  "status": "ok",
  "timestamp": "2025-05-23T12:34:56.789Z",
  "service": "chameleon-key-vault",
  "version": "0.1.0"
}
```

**Status Codes:**
- `200 OK` – Service is healthy

---

### 2. Readiness Probe

#### GET /ready

Check if service is ready to accept requests (GCP connectivity verified).

**Response:**
```json
{
  "ready": true,
  "timestamp": "2025-05-23T12:34:56.789Z"
}
```

**Status Codes:**
- `200 OK` – Service ready
- `503 Service Unavailable` – Dependencies (Firestore, KMS) unreachable

---

### PII Registry

#### GET /pii-registry/resources

List PII control-plane resources. Optional query filters:

- `system` such as `bigquery`, `hubspot`, or `salesforce`
- `ownerConnector` such as `dbt` or `pipelines`
- `scanEnabled` as `true` or `false`

Response includes registry metadata only: resource IDs, resource layer, visibility, classifications, handling policy, evidence pointers, and scan policy. It must not include raw PII.

#### GET /pii-registry/resources/:resourceId

Return one registry resource plus its policy evaluation. URL-encode `resourceId` values that contain `:` or `/`.

#### GET /pii-registry/policy

Return aggregate registry policy status and per-resource issues for dbt/demo clients.

### Warehouse Discovery Events

Warehouse metadata discovery is reported through `POST /lineage/events`; there is no separate ingestion endpoint for the MVP.

Pipelines should send resource-level events with `userId` set to `UNKNOWN` so Key Vault records audit evidence without adding a destination to the user-level Firestore hot path used by Janitor.

Example:

```json
{
  "eventType": "WAREHOUSE_METADATA_DISCOVERED",
  "dataClassification": "METADATA",
  "userId": "UNKNOWN",
  "source": "bigquery_metadata_crawler",
  "destination": "bigquery:your-gcp-project-id.chameleon_dev.stg_users",
  "operationId": "metadata-crawl:your-gcp-project-id.chameleon_dev.stg_users",
  "context": {
    "resource_id": "bigquery:your-gcp-project-id.chameleon_dev.stg_users",
    "system": "bigquery",
    "project_id": "your-gcp-project-id",
    "dataset_id": "chameleon_dev",
    "table_id": "stg_users",
    "registry_status": "DRIFTED",
    "column_count": 8,
    "new_columns": ["marketing_email"],
    "missing_registry_columns": [],
    "recommended_action": "classify_new_columns"
  }
}
```

This event must never contain sampled values or raw PII. Use column names, resource IDs, counts, confidence, and recommended actions only.

---

### 3. Generate Encryption Key

#### POST /key/generate

Create a new encryption key for a user. If a key already exists, returns the existing key status.

**Request:**
```json
{
  "userId": "user123"
}
```

**Parameters:**
- `userId` (string, required) – Alphanumeric, 1-64 characters. Identifies the user uniquely.

**Response (New Key):**
```json
{
  "status": "GENERATED",
  "userId": "user123",
  "timestamp": "2025-05-23T12:34:56.789Z"
}
```

**Response (Key Exists):**
```json
{
  "status": "EXISTS",
  "userId": "user123",
  "timestamp": "2025-05-23T12:34:56.789Z"
}
```

**Status Codes:**
- `201 Created` – New key generated
- `200 OK` – Key already exists
- `400 Bad Request` – Validation failed (invalid userId)
- `500 Internal Server Error` – GCP service error

**Example:**
```bash
curl -X POST http://localhost:3000/key/generate \
  -H "Content-Type: application/json" \
  -d '{"userId": "user123"}'
```

---

### 4. Encrypt Plaintext

#### POST /encrypt

**[DEMO ONLY]** Encrypt user PII using the user's DEK. Uses deterministic AES-256-GCM. Production systems should use randomized encryption context via `/key/:userId/encryption-context`.

**Request:**
```json
{
  "plaintext": "john.doe@example.com",
  "userId": "user123"
}
```

**Parameters:**
- `plaintext` (string, required) – Data to encrypt. Max 10KB.
- `userId` (string, required) – User ID (must have generated key first).

**Response:**
```json
{
  "ciphertext": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8gISIjJCUmJygpKissMi8gISIjJCUmJygpKissMy8g",
  "userId": "user123",
  "timestamp": "2025-05-23T12:34:56.789Z"
}
```

**Response Fields:**
- `ciphertext` (string) – Base64-encoded encrypted data. **Deterministic:** same plaintext + userId + key = same ciphertext.
- `userId` (string) – Echo of request userId
- `timestamp` (string) – ISO 8601 timestamp

**Status Codes:**
- `200 OK` – Successfully encrypted
- `400 Bad Request` – Validation failed (invalid plaintext/userId/base64)
- `404 Not Found` – User key not found (generate key first)
- `500 Internal Server Error` – GCP service error

**Example:**
```bash
curl -X POST http://localhost:3000/encrypt \
  -H "Content-Type: application/json" \
  -d '{
    "plaintext": "john.doe@example.com",
    "userId": "user123"
  }'
```

---

### 5. Decrypt Ciphertext

#### POST /decrypt

**[DEMO ONLY]** Decrypt ciphertext using the user's DEK. Verifies GCM authentication tag (fails if tampered).

**Request:**
```json
{
  "ciphertext": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8gISIjJCUmJygpKissMi8gISIjJCUmJygpKissMy8g",
  "userId": "user123"
}
```

**Parameters:**
- `ciphertext` (string, required) – Base64-encoded ciphertext from `/encrypt` response
- `userId` (string, required) – User ID

**Response:**
```json
{
  "plaintext": "john.doe@example.com",
  "userId": "user123",
  "timestamp": "2025-05-23T12:34:56.789Z"
}
```

**Status Codes:**
- `200 OK` – Successfully decrypted
- `400 Bad Request` – Validation failed or ciphertext tampered (GCM tag invalid)
- `404 Not Found` – User key not found or has been shredded
- `500 Internal Server Error` – GCP service error

**Example:**
```bash
curl -X POST http://localhost:3000/decrypt \
  -H "Content-Type: application/json" \
  -d '{
    "ciphertext": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8gISIjJCUmJygpKissMi8gISIjJCUmJygpKissMy8g",
    "userId": "user123"
  }'
```

---

### 6. Query Key Status

#### GET /key-status/:userId

Get the lifecycle status of a user's encryption key.

**Path Parameters:**
- `userId` (string, required) – Alphanumeric, 1-64 characters

**Response:**
```json
{
  "userId": "user123",
  "status": "ACTIVE",
  "createdAt": "2025-05-23T10:00:00.000Z",
  "shredAt": null,
  "rotatedAt": null,
  "timestamp": "2025-05-23T12:34:56.789Z"
}
```

**Status Enum:**
- `ACTIVE` – Key available for encryption/decryption
- `ROTATED` – Key was rotated to new version (old key preserved for legacy data)
- `SHREDDED` – Key destroyed (all data encrypted with this key is now unrecoverable)

**Response Fields:**
- `status` (enum) – Current key lifecycle state
- `createdAt` (ISO8601) – When key was first generated
- `shredAt` (ISO8601) – When key was destroyed (if status = SHREDDED)
- `rotatedAt` (ISO8601) – When key was rotated (if status = ROTATED)

**Status Codes:**
- `200 OK` – Key found
- `400 Bad Request` – Invalid userId format
- `404 Not Found` – User key not found
- `500 Internal Server Error` – GCP service error

**Example:**
```bash
curl http://localhost:3000/key-status/user123
```

---

### 7. Shred (Destroy) Encryption Key

#### DELETE /key/shred

Initiate the "mathematical erasure" process. This endpoint marks the key for destruction and triggers the deletion request lifecycle, which orchestrates the Janitor cascade across downstream systems.

**Request:**
```json
{
  "userId": "user123"
}
```

**Parameters:**
- `userId` (string, required) – User ID

**Response:**
```json
{
  "status": "SHREDDED",
  "userId": "user123",
  "timestamp": "2025-05-23T12:34:56.789Z",
  "message": "Key destroyed. All encrypted data is now mathematically unrecoverable."
}
```

**Status Codes:**
- `200 OK` – Key successfully shredded (or already shredded)
- `400 Bad Request` – Validation failed
- `404 Not Found` – User key not found
- `500 Internal Server Error` – GCP service error

**Side Effects:**
- User's key is marked as `SHREDDED` in Firestore
- Subsequent `/decrypt` calls for this user will return `404`
- Subsequent `/encrypt` calls for this user will return `404`
- Operation is permanent and irreversible

**Example:**
```bash
curl -X DELETE http://localhost:3000/key/shred \
  -H "Content-Type: application/json" \
  -d '{"userId": "user123"}'
```

---

### 8. Record Lineage Event

#### POST /lineage/events

Record the movement of encrypted user data from a source to a destination. Note: Do not include actual encrypted PII in the payload; this endpoint tracks metadata only.

**Request:**
```json
{
  "userId": "user123",
  "source": "ingestion-api",
  "destination": "bigquery-raw",
  "eventType": "DATA_MOVEMENT",
  "context": {
    "jobId": "sync-001",
    "table": "users_pii"
  }
}
```

**Response:**
```json
{
  "status": "RECORDED",
  "eventId": "01H2BEZ9...",
  "timestamp": "2025-05-23T12:34:56.789Z"
}
```

**Status Codes:**
- `201 Created` – Event recorded
- `400 Bad Request` – Validation failed

---

### 9. Get User Lineage

#### GET /lineage/user/:userId

List all downstream destinations currently holding data for this user.

**Response:**
```json
{
  "userId": "user123",
  "destinations": [
    {
      "name": "bigquery-raw",
      "lastSeen": "2025-05-23T12:00:00.000Z"
    },
    {
      "name": "hubspot",
      "lastSeen": "2025-05-22T10:00:00.000Z"
    }
  ],
  "timestamp": "2025-05-23T12:34:56.789Z"
}
```

---

### 10. Get Deletion Plan

#### GET /lineage/deletion-plan/:userId

Preview the impact of a shredding operation. Lists all systems that will receive "Janitor" wipe requests.

**Response:**
```json
{
  "userId": "user123",
  "impactedDestinations": ["hubspot", "salesforce", "segment"],
  "mathematicalErasure": {
    "status": "PENDING",
    "stores": ["bigquery", "gcs-audit-logs"]
  },
  "timestamp": "2025-05-23T12:34:56.789Z"
}
```

**Status Codes:**
- `200 OK` – Plan generated
- `404 Not Found` – User not found in lineage graph

---

### 11. Rotate User Key

#### POST /key/rotate

Generates a new Data Encryption Key (DEK) for the user. Subsequent `/encrypt` calls will use the new key. Note: Existing ciphertexts are not automatically re-encrypted; the service must maintain access to old key versions for decryption unless a background migration is triggered.

**Request:**
```json
{
  "userId": "user123"
}
```

**Response:**
```json
{
  "status": "ROTATED",
  "userId": "user123",
  "timestamp": "2025-05-23T12:34:56.789Z"
}
```

**Status Codes:**
- `200 OK` – Key successfully rotated
- `400 Bad Request` – Validation failed
- `404 Not Found` – User key not found or shredded
- `500 Internal Server Error` – GCP service error

---

### 12. Get Encryption Context

#### GET /key/:userId/encryption-context

Retrieve metadata and the wrapped Data Encryption Key (DEK) for performing local randomized encryption and tokenization in downstream data planes.

**Response:**
```json
{
  "userId": "user123",
  "keyId": "v1",
  "encryptedDek": "...",
  "algorithm": "AES-256-GCM",
  "encryptionVersion": "v2",
  "tokenization": {
    "algorithm": "HMAC-SHA256",
    "tokenKeyId": "..."
  },
  "status": "ACTIVE",
  "timestamp": "2026-06-02T12:00:00Z"
}
```

---

### 13. Deletion Requests

#### POST /deletion-requests
Create a new deletion lifecycle tracking object.

#### GET /deletion-requests/:deletionRequestId
Query the status of a specific deletion request, including the progress of Janitor wipes.

#### POST /deletion-requests/:deletionRequestId/advance
Manually advance the state of a deletion request (e.g., from `KEY_DESTROYED` to `CASCADE_PENDING`).

---

### 14. Janitor Events

#### POST /janitor-events

Callback endpoint for data planes to report the outcome of SaaS wipe operations.

**Request:**
```json
{
  "deletionRequestId": "...",
  "userId": "user123",
  "destination": "hubspot",
  "status": "SAAS_WIPE_SUCCEEDED",
  "attemptNumber": 1,
  "timestamp": "..."
}
```

---

### 15. Get Destruction Certificate

#### GET /certificate/:userId

Retrieve a signed JWT proving the mathematical erasure of a user's data.

---

### 16. Get Signing Public Key

#### GET /public-key

Retrieve the PEM-encoded public key used to verify certificates.

## Error Codes & Meanings

| Code | Scenario | Explanation |
|------|----------|-------------|
| 400 | Validation Error | Invalid input format (non-alphanumeric userId, empty plaintext, invalid base64, oversized payload) |
| 400 | Tampered Ciphertext | GCM authentication tag validation failed on `/decrypt` (data was modified) |
| 404 | Key Not Found | User has no key, or key was already shredded |
| 500 | GCP Service Error | Firestore, Cloud KMS, or Secret Manager is unreachable |

---

## Encryption Details

### Deterministic AES-256-GCM

**Note on Determinism:**
While v1 used deterministic encryption for indexing, Chameleon v2 shifts towards **randomized encryption** at the data plane for enhanced security, using Repo 2 as the control plane to manage keys. Deterministic mode remains available for legacy compatibility and specific use cases.

**Deterministic Algorithm (Legacy/Demo):**
- Reproducible audits

**Algorithm:**
```
IV = SHA256(userId) truncated to 12 bytes (deterministic)
AAD = userId (prevents cross-user decryption)
Mode = AES-256-GCM (Galois/Counter Mode)

Ciphertext = AES-GCM-Encrypt(plaintext, DEK, IV, AAD)
Ciphertext is stored as: encrypted_data || auth_tag (combined, base64-encoded)
```

**Key Sizes:**
- DEK: 32 bytes (256 bits)
- IV: 12 bytes (96 bits)
- Auth Tag: 16 bytes (128 bits)

**Security Properties:**
- **Authenticated Encryption:** GCM detects any tampering
- **Deterministic:** Same input always produces same output
- **IV Derivation:** IV derived from userId (not random, but different per user)
- **AAD:** Additional Authenticated Data prevents decryption with wrong userId

---

## Rate Limiting

Currently not implemented. Will be added in Phase 2d.

---

## Versioning

**API Version:** `0.1.0`  
**Status:** Phase 2b (Endpoints)  
**Last Updated:** 2025-05-23

---

## Examples

### Complete Flow: Encrypt → Decrypt → Shred → Fail

```bash
# 1. Generate key for user
curl -X POST http://localhost:3000/key/generate \
  -H "Content-Type: application/json" \
  -d '{"userId": "user123"}'
# Response: {"status": "GENERATED"}

# 2. Encrypt email
curl -X POST http://localhost:3000/encrypt \
  -H "Content-Type: application/json" \
  -d '{"plaintext": "john@example.com", "userId": "user123"}'
# Response: {"ciphertext": "ABC123...", "userId": "user123"}
# Save ciphertext for next step

# 3. Decrypt to verify
curl -X POST http://localhost:3000/decrypt \
  -H "Content-Type: application/json" \
  -d '{"ciphertext": "ABC123...", "userId": "user123"}'
# Response: {"plaintext": "john@example.com"}

# 4. Delete user (shred key)
curl -X DELETE http://localhost:3000/key/shred \
  -H "Content-Type: application/json" \
  -d '{"userId": "user123"}'
# Response: {"status": "SHREDDED"}

# 5. Try decrypt after shredding (should fail)
curl -X POST http://localhost:3000/decrypt \
  -H "Content-Type: application/json" \
  -d '{"ciphertext": "ABC123...", "userId": "user123"}'
# Response: 404 {"error": "User key not found or has been shredded"}
```

---

## Related Documentation

- [CLAUDE.md](CLAUDE.md) – Development setup
- [ARCHITECTURE.md](ARCHITECTURE.md) – Design decisions

### 12. Get Destruction Certificate

#### GET /certificate/:userId

Retrieve a signed JWT proving the mathematical erasure of a user's data.

**Response:**
```json
{
  "certificate": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "userId": "user123",
  "timestamp": "2025-05-23T12:34:56.789Z"
}
```

---

### 13. Get Signing Public Key

#### GET /public-key

Retrieve the PEM-encoded public key used to verify certificates.

**Response:**
```json
{
  "publicKey": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "algorithm": "RSA_SIGN_PSS_2048_SHA256",
  "timestamp": "2025-05-23T12:34:56.789Z"
}
```
