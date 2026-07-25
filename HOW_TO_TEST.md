# HOW TO TEST: Project Chameleon End-to-End Flow

This document provides the step-by-step guide to testing the full "Right to be Forgotten" lifecycle in Project Chameleon, as verified in June 2026.

## 1. Setup & Prerequisites

Ensure your `.env` file is configured with the correct GCP project details and that the `CLOUD_KMS_SIGNING_KEY_NAME` uses the full versioned resource path:
`projects/your-gcp-project-id/locations/us-central1/keyRings/chameleon-dev/cryptoKeys/chameleon-cert-signing-dev/cryptoKeyVersions/1`

Use a tenant header throughout the test. Example:
`X-Tenant-Id: tenant-e2e-dev`

**Terminal 1:** Start the service
```bash
npm run dev
```

---

## 2. The Testing Lifecycle

Run these commands in a **separate terminal tab**. 

### Step A: Identity Provisioning (Key Generation)
Create the user's cryptographic identity in Firestore.
```bash
curl -X POST http://localhost:8080/key/generate \
  -H "Content-Type: application/json" \
  -H "X-Tenant-Id: tenant-e2e-dev" \
  -d '{"userId": "user-test-final-004"}'
```
*   **Check Firestore:** Look in the `key_registry` collection for `user-test-final-004`. Status should be `ACTIVE`.
*   **Check BigQuery:** Verify the `key-generation-audit` event appears in `lineage_db.events`.

### Step B: Fetch Encryption Context (v2 Standard)
Simulate the Repo 3 workflow to retrieve the encryption policy and wrapped DEK.
```bash
curl http://localhost:8080/key/user-test-final-004/encryption-context \
  -H "X-Tenant-Id: tenant-e2e-dev"
```

### Step C: Data Protection (Demo Encryption)
Simulate protecting PII. **Copy the ciphertext** from the response for the later erasure test.
```bash
curl -X POST http://localhost:8080/encrypt \
  -H "Content-Type: application/json" \
  -H "X-Tenant-Id: tenant-e2e-dev" \
  -d '{"userId": "user-test-final-004", "plaintext": "pi-data@example.com"}'
```

### Step C: Record Data Flow (Lineage Tracking)
Record data movement to HubSpot and Salesforce to populate the Janitor's map.
```bash
# Record flow to HubSpot
curl -X POST http://localhost:8080/lineage/events \
  -H "Content-Type: application/json" \
  -H "X-Tenant-Id: tenant-e2e-dev" \
  -d '{"userId": "user-test-final-004", "source": "api-ingestion", "destination": "hubspot", "dataClassification": "UNSTRUCTURED_CACHE"}'

# Record flow to Salesforce
curl -X POST http://localhost:8080/lineage/events \
  -H "Content-Type: application/json" \
  -H "X-Tenant-Id: tenant-e2e-dev" \
  -d '{"userId": "user-test-final-004", "source": "hubspot-export", "destination": "salesforce", "dataClassification": "ENCRYPTED_ONLY"}'
```

### Step D: The "Kill Switch" (Key Shredding)
Destroy the key to execute mathematical erasure and trigger the Janitor cascade.
```bash
curl -X DELETE http://localhost:8080/key/shred \
  -H "Content-Type: application/json" \
  -H "X-Tenant-Id: tenant-e2e-dev" \
  -d '{"userId": "user-test-final-004"}'
```
*   **Check Server Logs:** Watch for `JanitorService` logs attempting wipe requests.

---

## 3. Verification of Erasure

### Step E: Mathematical Proof (Decryption Failure)
Try to decrypt the ciphertext you saved in **Step B**.
```bash
curl -i -X POST http://localhost:8080/decrypt \
  -H "Content-Type: application/json" \
  -H "X-Tenant-Id: tenant-e2e-dev" \
  -d '{"userId": "user-test-final-004", "ciphertext": "PASTE_YOUR_CIPHERTEXT_HERE"}'
```
*   **Expected Result:** `404 Not Found`. This proves the data is now unrecoverable.

### Step F: Compliance Proof (Certificate of Destruction)
Retrieve the cryptographically signed JWT proof.
```bash
curl http://localhost:8080/certificate/user-test-final-004 \
  -H "X-Tenant-Id: tenant-e2e-dev"
```
*   **Verification:** Decode the JWT (via `jwt.io` or `base64 -d`) to see the `shredDate` and the summary of erased systems (`hubspot`, `salesforce`).

### Step G: Dead Letter Queue (DLQ) Audit
Verify that failed SaaS wipe attempts (due to placeholder keys) were captured for manual review.
```bash
bq query --use_legacy_sql=false \
"SELECT * FROM \`your-gcp-project-id.lineage_db.janitor_failed_wipes\` WHERE JSON_EXTRACT_SCALAR(data, '$.userId') = 'user-test-final-004'"
```

---

## Summary Checklist

| Step | Action | Success Signal |
|------|--------|----------------|
| 1 | Key Gen | `201 Created` / Firestore Entry |
| 2 | Lineage | Events in BigQuery `events` table |
| 3 | Shred | Status `SHREDDED` in Firestore |
| 4 | Decrypt | `404 Not Found` (Mathematical Proof) |
| 5 | Cert | Signed JWT issued with lineage summary |
| 6 | DLQ | Failure logs in `janitor_failed_wipes` |

---

## 4. Two-User Batch E2E Smoke Test

This is the current recommended smoke test for the Key Vault and pipelines contract. It verifies batch key generation, batch encryption context retrieval, lineage writes, shredding, decryption failure, and certificate generation for two users under the same tenant.

Start the service in one terminal:

```bash
npm run dev
```

Run the test in a second terminal:

```bash
export VAULT_URL=http://localhost:8080
export TENANT_ID=tenant-e2e-dev
export USER_1=user-e2e-001
export USER_2=user-e2e-002
```

Generate keys for both users:

```bash
curl -sS -X POST "$VAULT_URL/keys/batch-generate" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-Id: $TENANT_ID" \
  -d "{\"tenantId\":\"$TENANT_ID\",\"userIds\":[\"$USER_1\",\"$USER_2\"]}" | jq
```

Fetch encryption contexts for both users:

```bash
curl -sS -X POST "$VAULT_URL/keys/batch-encryption-context" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-Id: $TENANT_ID" \
  -d "{\"tenantId\":\"$TENANT_ID\",\"userIds\":[\"$USER_1\",\"$USER_2\"]}" | jq
```

Record lineage for both users:

```bash
curl -sS -X POST "$VAULT_URL/lineage/events" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-Id: $TENANT_ID" \
  -d "{\"userId\":\"$USER_1\",\"source\":\"api-ingestion\",\"destination\":\"hubspot\",\"dataClassification\":\"UNSTRUCTURED_CACHE\"}" | jq

curl -sS -X POST "$VAULT_URL/lineage/events" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-Id: $TENANT_ID" \
  -d "{\"userId\":\"$USER_2\",\"source\":\"api-ingestion\",\"destination\":\"salesforce\",\"dataClassification\":\"ENCRYPTED_ONLY\"}" | jq
```

Verify lineage before shredding:

```bash
curl -sS "$VAULT_URL/lineage/user/$USER_1" \
  -H "X-Tenant-Id: $TENANT_ID" | jq

curl -sS "$VAULT_URL/lineage/user/$USER_2" \
  -H "X-Tenant-Id: $TENANT_ID" | jq
```

Encrypt sample PII and save ciphertexts:

```bash
export CT_1=$(curl -sS -X POST "$VAULT_URL/encrypt" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-Id: $TENANT_ID" \
  -d "{\"userId\":\"$USER_1\",\"plaintext\":\"user-1@example.com\"}" | jq -r '.ciphertext')

export CT_2=$(curl -sS -X POST "$VAULT_URL/encrypt" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-Id: $TENANT_ID" \
  -d "{\"userId\":\"$USER_2\",\"plaintext\":\"user-2@example.com\"}" | jq -r '.ciphertext')

echo "$CT_1"
echo "$CT_2"
```

Shred both users:

```bash
curl -sS -X DELETE "$VAULT_URL/key/shred" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-Id: $TENANT_ID" \
  -d "{\"userId\":\"$USER_1\",\"operationId\":\"e2e-shred-$USER_1\"}" | jq

curl -sS -X DELETE "$VAULT_URL/key/shred" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-Id: $TENANT_ID" \
  -d "{\"userId\":\"$USER_2\",\"operationId\":\"e2e-shred-$USER_2\"}" | jq
```

Confirm decrypt fails after shredding:

```bash
curl -i -sS -X POST "$VAULT_URL/decrypt" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-Id: $TENANT_ID" \
  -d "{\"userId\":\"$USER_1\",\"ciphertext\":\"$CT_1\"}"

curl -i -sS -X POST "$VAULT_URL/decrypt" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-Id: $TENANT_ID" \
  -d "{\"userId\":\"$USER_2\",\"ciphertext\":\"$CT_2\"}"
```

Fetch certificates:

```bash
curl -sS "$VAULT_URL/certificate/$USER_1" \
  -H "X-Tenant-Id: $TENANT_ID" | jq

curl -sS "$VAULT_URL/certificate/$USER_2" \
  -H "X-Tenant-Id: $TENANT_ID" | jq
```

Expected results:

- Batch generation and context retrieval return success for both users.
- Firestore stores tenant-scoped key documents.
- BigQuery lineage events include `tenant_id`.
- Decrypt returns `404` after shredding.
- Certificates are issued for both users and include tenant-scoped lineage summaries.

## 5. Cross-Tenant Same-User Isolation Test

Run this after the two-user smoke when validating tenant isolation specifically. This uses the same `userId` in two tenants and shreds only one tenant.

```bash
export VAULT_URL=http://localhost:8080
export USER_ID=user-cross-tenant-001
export TENANT_A=tenant-e2e-a
export TENANT_B=tenant-e2e-b
```

Create the same user in both tenants:

```bash
curl -sS -X POST "$VAULT_URL/key/generate" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-Id: $TENANT_A" \
  -d "{\"userId\":\"$USER_ID\"}" | jq

curl -sS -X POST "$VAULT_URL/key/generate" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-Id: $TENANT_B" \
  -d "{\"userId\":\"$USER_ID\"}" | jq
```

Record different lineage per tenant:

```bash
curl -sS -X POST "$VAULT_URL/lineage/events" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-Id: $TENANT_A" \
  -d "{\"userId\":\"$USER_ID\",\"source\":\"api-ingestion\",\"destination\":\"hubspot\",\"dataClassification\":\"UNSTRUCTURED_CACHE\"}" | jq

curl -sS -X POST "$VAULT_URL/lineage/events" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-Id: $TENANT_B" \
  -d "{\"userId\":\"$USER_ID\",\"source\":\"api-ingestion\",\"destination\":\"salesforce\",\"dataClassification\":\"ENCRYPTED_ONLY\"}" | jq
```

Shred only tenant A:

```bash
curl -sS -X DELETE "$VAULT_URL/key/shred" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-Id: $TENANT_A" \
  -d "{\"userId\":\"$USER_ID\",\"operationId\":\"e2e-shred-$TENANT_A-$USER_ID\"}" | jq
```

Tenant A should be shredded and tenant B should still have an active encryption context:

```bash
curl -i -sS "$VAULT_URL/key/$USER_ID/encryption-context" \
  -H "X-Tenant-Id: $TENANT_A"

curl -sS "$VAULT_URL/key/$USER_ID/encryption-context" \
  -H "X-Tenant-Id: $TENANT_B" | jq
```

Fetch the tenant A certificate and verify the lineage summary only includes tenant A destinations:

```bash
curl -sS "$VAULT_URL/certificate/$USER_ID" \
  -H "X-Tenant-Id: $TENANT_A" | jq
```
