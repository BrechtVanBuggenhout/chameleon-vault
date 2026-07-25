# Chameleon Key Vault - Architecture & Design Decisions

## System Architecture

```text
┌────────────────────────────────────────────────────────┐
│              Client Applications                        │
│        (Data Pipeline, ETL, Third-party SaaS)          │
└────────────────────┬─────────────────────────────────┘
                     │
                     │ REST API (HTTP/HTTPS)
                     │
┌────────────────────▼─────────────────────────────────┐
│         Fastify API Server (Port 3000)               │
├────────────────────────────────────────────────────┤
│                                                    │
│  ┌─────────────────────────────────────────────┐ │
│  │  Crypto Module (Deterministic AES-256-GCM) │ │
│  │  - encrypt(plaintext, userId, DEK)         │ │
│  │  - decrypt(ciphertext, userId, DEK)        │ │
│  │  - generateRandomDEK()                     │ │
│  │  - generateDeterministicIV(userId)         │ │
│  └─────────────────────────────────────────────┘ │
│                     ▲                             │
│                     │                             │
│  ┌─────────────────────────────────────────────┐ │
│  │  Route Handlers (src/routes/crypto.ts)    │ │
│  │  - POST /encrypt                          │ │
│  │  - POST /decrypt                          │ │
│  │  - POST /key/generate                     │ │
│  │  - DELETE /key/shred                      │ │
│  │  - GET /key-status/:userId                │ │
│  │  - GET /key/:userId/encryption-context    │ │
│  │  - POST /deletion-requests                │ │
│  └─────────────────────────────────────────────┘ │
│                     ▲                             │
│                     │                             │
│  ┌─────────────────────────────────────────────┐ │
│  │  Validation Middleware (Joi)               │ │
│  │  - userId: alphanumeric, 1-64 chars       │ │
│  │  - plaintext: 1-10KB string                │ │
│  │  - ciphertext: valid base64                │ │
│  └─────────────────────────────────────────────┘ │
│                     ▲                             │
└────────────────────┼─────────────────────────────┘
                     │
      ┌──────────────┼──────────────┬──────────────┐
      │              │              │              │
      ▼              ▼              ▼              ▼
   Firestore     Cloud KMS    Secret Manager   Cloud Logging
  (Key Store)  (Key Encrypt)  (CMEK Metadata)  (Audit Logs)
```

---

## Control Plane vs. Data Plane
Chameleon v2 adopts a split architecture. This service (Repo 2) acts as the **Control Plane**, managing the lifecycle of keys and deletion requests. High-volume data processing occurs in the **Data Plane** (Repo 3), which fetches encryption context from Repo 2 and performs local encryption/decryption.

## Design Decisions

### 1. Hybrid Encryption (Randomized by Default)
**Decision:** Shift from deterministic encryption to randomized AES-256-GCM for PII at rest.

**Why:**
- **Database Joins:** Same plaintext always encrypts to same ciphertext, enabling SQL joins on encrypted columns
- **Efficient Deduplication:** Can identify duplicate data without decryption
- **Audit Reproducibility:** Same scenario produces same result (useful for compliance)

**Trade-off:**
- Less secure against pattern analysis (attacker sees same email encrypts the same way)
- **Mitigated by:** Using different keys per user + AAD (userId) prevents cross-user correlation
- **V2 Strategy:** Use randomized IVs in Repo 3 for data storage; use deterministic derivation only for secondary indices or lookup tokens.

**Implementation:**
- **Data Plane (Repo 3):** Standard randomized AES-GCM (12-byte random IV).
- **Control Plane (Repo 2):** Provides wrapped DEKs via `/encryption-context`.

---

### 2. Node.js + Fastify (vs. Rust or Python)

**Decision:** Node.js 20 + Fastify framework.

**Why:**
- **Development Speed:** Ship Milestone 2 faster with familiar async/await patterns
- **GCP Integration:** Official Google Cloud SDKs well-maintained in TypeScript
- **Team Scaling:** More Node developers available than Rust
- **Bottleneck Analysis:** Latency is GCP API calls (100-200ms), not crypto (1-5ms)

**Rust would be better if:**
- We needed sub-50ms cold starts on Cloud Run (we don't)
- Processing millions of local encryptions/sec (we don't)
- Embedded in high-frequency trading systems (we're not)

---

### 3. Single DEK per User (vs. DEK per Data Item)

**Decision:** One 32-byte DEK per user, used for all their data.

**Why:**
- **Simplicity:** Easy to manage, rotate, and shred
- **Cost:** Firestore storage for N users, not N × M items
- **Shredding:** One key destruction = one audit log entry
- **Key Rotation:** Rotate one key = re-encrypt all user data (batched offline)

**Trade-off:**
- If one plaintext is compromised → all user's data is at risk (same key)
- **Mitigated by:** Different userId → different IV → same plaintext looks different per user

---

### 4. Firestore as Key Registry (vs. Cloud SQL)

**Decision:** Firestore for MVP, migration path to Cloud SQL PostgreSQL.

**Why:**
- **MVP Speed:** No schema migrations, flexible document structure
- **Operational:** Serverless (no ops burden), automatic backups
- **CMEK:** Supports customer-managed encryption keys
- **Free Tier:** 1GB storage, 50k reads/day

**Trade-off:**
- Less operational control than PostgreSQL
- **Plan:** Migrate to PostgreSQL for production (ACID + immutable audit logs)

---

### 5. Joi Validation (vs. Zod, Yup, AJV)

**Decision:** Joi for request validation.

**Why:**
- **Mature:** Industry standard, extensive error messages
- **Powerful:** Fluent API with custom validators
- **Well-Tested:** Used at scale in production systems
- **Integration:** Works well with Fastify ecosystem

---

### 6. Pino Logging (vs. Winston, Bunyan)

**Decision:** Pino for structured logging.

**Why:**
- **Performance:** Fastest structured JSON logger in Node.js
- **GCP Integration:** Structured logging matches Cloud Logging format
- **Child Loggers:** Module-scoped loggers track context (crypto, firestore, routes)
- **Cloud-Native:** Designed for serverless (cold start optimized)

---

## Security Model

### Threat Model

| Threat | Mitigation |
|--------|-----------|
| **Malicious Admin** | Encryption keys separate from data; admin can't decrypt without key access |
| **Database Breach** | Encrypted data is useless without DEK; keys stored separately in Firestore |
| **Backup Exposure** | Keys destroyed = backups automatically unrecoverable (mathematical erasure) |
| **Network Sniffing** | All traffic TLS 1.2+ (enforced by Cloud Run) |
| **Key Compromise** | Cloud KMS tracks access; 90-day rotation policy limits exposure window |
| **Tampering** | GCM authentication tag detects any ciphertext modification |
| **Replay Attacks** | Each request is unique; timestamp-based audit log |
| **Cross-User Attacks** | AAD (userId) prevents decryption with wrong userId |
| **Material Exposure** | DEKs are only unmasked in memory; shredded keys have their material physically purged from storage. |

### Key Material Shredding
Unlike simple logical deletion, `DELETE /key/shred` triggers a physical removal of the encrypted DEK material from the Firestore document. This ensures that even if the storage layer is compromised, the data remains cryptographically irrecoverable.


### Encryption Layers

1. **Application Layer:** AES-256-GCM (this service)
2. **KMS Layer:** Cloud KMS (DEK encryption for storage)
3. **Storage Layer:** Firestore CMEK (key registry encryption)
4. **Audit Layer:** Cloud Logging encryption in GCS

### Deletion State Machine
1. **SHRED_REQUESTED**: Deletion request created.
2. **KEY_DESTROYED**: DEK material removed from registry.
3. **CASCADE_PENDING**: Janitor wipes identified.
4. **CASCADE_IN_PROGRESS**: Webhooks/Tasks dispatched to SaaS connectors.
5. **CASCADE_COMPLETE**: All systems report success.
6. **CERTIFICATE_ISSUED**: Signed proof of destruction generated.

---

## Data Flow

### Encryption Flow

```
Client Request
    │
    ├─ POST /encrypt {plaintext, userId}
    │
    ├─ Validate input (Joi schema)
    │   ├─ userId: alphanumeric, 1-64 chars
    │   └─ plaintext: non-empty, < 10KB
    │
    ├─ Get DEK from Firestore
    │   ├─ Query: collection.doc(userId).get()
    │   └─ Check status ≠ SHREDDED
    │
    ├─ Encrypt with DeterministicAES
    │   ├─ IV = SHA256(userId)[0:12]
    │   ├─ Cipher = AES-256-GCM(plaintext, DEK, IV, AAD=userId)
    │   └─ Auth Tag appended to ciphertext
    │
    └─ Return: {ciphertext: base64, userId, timestamp}
```

### Decryption Flow

```
Client Request
    │
    ├─ POST /decrypt {ciphertext, userId}
    │
    ├─ Validate input (Joi schema)
    │   ├─ ciphertext: valid base64
    │   └─ userId: alphanumeric, 1-64 chars
    │
    ├─ Get DEK from Firestore
    │   ├─ Query: collection.doc(userId).get()
    │   └─ Check status ≠ SHREDDED (return 404 if shredded)
    │
    ├─ Decrypt with DeterministicAES
    │   ├─ IV = SHA256(userId)[0:12] (same as encryption)
    │   ├─ Decipher = AES-256-GCM.decrypt(ciphertext, DEK, IV, AAD=userId)
    │   ├─ Verify GCM auth tag (throws if tampered)
    │   └─ Return plaintext
    │
    └─ Return: {plaintext, userId, timestamp}
       (or 400 if GCM validation failed / tampered)
```

### Key Shredding Flow

```
Client Request
    │
    ├─ DELETE /key/shred {userId}
    │
    ├─ Validate userId
    │
    ├─ Get current status from Firestore
    │   └─ Check key exists (404 if not)
    │
    ├─ Create Deletion Request (idempotent)
    │
    ├─ Purge Key Material
    │   ├─ SET status = SHREDDED
    │   ├─ SET shredAt = now()
    │   ├─ DELETE encryptedDek mapping
    │   └─ Firestore audit log captures change
    │
    ├─ Trigger Janitor Cascade
    ├─ Log to Cloud Logging
    │   └─ Event: KeyShredded {userId, timestamp, operator}
    │
    └─ Return: {status: SHREDDED, userId, timestamp}

Consequence:
    ├─ All encrypt() calls for this user now return 404
    ├─ All decrypt() calls for this user now return 404
    └─ User's data encrypted with DEK is mathematically unrecoverable
```

---

## Performance Considerations

### Latency Breakdown (estimated)

```
Request → Validation:        ~1ms
Validation → Firestore GET:  ~50-100ms (network round-trip)
Crypto (encrypt/decrypt):    ~1-5ms
JSON serialize:              <1ms
Response:                    Total ~50-110ms (per request)
```

**Bottleneck:** Firestore network latency dominates. Crypto is negligible.

### Optimization Opportunities (Future)

- **Caching:** DEK cache (with TTL) to reduce Firestore queries
- **Batching:** Bulk encrypt/decrypt for large datasets
- **Connection Pooling:** Reuse Firestore connections
- **Cloud Run Concurrency:** Increase max concurrent instances

---

## Testing Strategy

### Unit Tests (test/crypto.test.ts)
- ✅ Determinism (same input = same output)
- ✅ Correctness (decrypt returns plaintext)
- ✅ Tamper detection (GCM validation)
- ✅ Edge cases (unicode, empty strings, large payloads)
- ✅ 25+ test cases

### Integration Tests (test/api.integration.test.ts)
- ✅ All 5 endpoints
- ✅ Error scenarios (404, 400, 500)
- ✅ Validation rules
- ✅ Milestone 2 flow (encrypt → decrypt → shred → fail)

### Manual Testing
- Postman collection (TBD)
- Load testing with `k6` or `ab` (TBD Phase 2d)
- Security audit (TBD Phase 2d)

---

## Deployment Architecture

```
GitHub Repository
    │
    ├─ PR created → GitHub Actions runs
    │   ├─ npm run lint
    │   ├─ npm run type-check
    │   └─ npm test
    │
    ├─ PR approved + merged to main
    │   │
    │   └─ GitHub Actions runs
    │       ├─ Build Docker image
    │       ├─ Push to Artifact Registry
    │       └─ Deploy to Cloud Run
    │
    └─ Cloud Run instance running
        ├─ Requests routed via load balancer
        ├─ Auto-scales based on CPU/memory
        └─ Logs streamed to Cloud Logging
```

---

## Error Handling Strategy

| Error Type | Status | Handling |
|-----------|--------|----------|
| **Validation** | 400 | Return field + message, no retry |
| **Not Found** | 404 | Check userId, generate key if needed |
| **Auth Failed** | 401 | Service account credentials invalid |
| **Transient** | 503 | Exponential backoff retry (client-side) |
| **Unknown** | 500 | Log stack trace, return generic message |

---

## Future Improvements

### Phase 2d: Logging & Cloud Logging Export (✅ Complete)
- ✅ Structured JSON logging via Pino
- ✅ Cloud Logging integration for production
- ✅ Request correlation IDs for tracing
- ✅ Severity-based log filtering
- ✅ Module-scoped loggers
- 📋 Future: Prometheus metrics (encrypt/decrypt latency, error rates)
- 📋 Future: Cloud Trace integration (distributed tracing)
- 📋 Future: Custom Cloud Monitoring dashboards

### Phase 3: Lineage Engine
- Track data flow: user → dataset → external tool
- Trigger Janitor webhooks on key shredding
- Immutable lineage ledger

### Phase 4: Certificate of Destruction
- Cryptographic proof of erasure
- Audit trail fingerprinting
- Verification endpoint for auditors

### Phase 5: Multi-Tenant Support
- Project-scoped keys
- Billing per-project
- Data residency controls

---

## References

- [Node.js Crypto Module](https://nodejs.org/api/crypto.html)
- [AES-256-GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
- [Cloud KMS Best Practices](https://cloud.google.com/kms/docs/best-practices)
- [GCP CMEK](https://cloud.google.com/docs/security/encryption/cmek)
- [Firestore CMEK](https://cloud.google.com/firestore/docs/firestore-cmek)
