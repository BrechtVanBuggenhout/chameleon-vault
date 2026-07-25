# Deploy Checklist — Declare-PII + Auto-Discovery + Coverage

One runbook to ship the **declare-PII** feature (users register ETL/Fivetran tables as PII),
the **crawler discover→declare loop** (Chameleon finds undeclared tables and one-click
declares them), and the **crypto-shred coverage score** (headline "% of PII that is
shreddable" gauge). Built 2026-07-02; **uncommitted and undeployed** at time of writing.

Spans four repos:
- `chameleon-key-vault` — declare API + discovery read endpoint + coverage endpoint (control plane)
- `chameleon-console` — declare slide-over + discovered-undeclared banner + coverage gauge
- `chameleon-data-pipelines` — `/api/v1/warehouse-crawl` endpoint (runs the crawler)
- `chameleon-infra-gcp` — Secret Manager, IAM, Cloud Run env, Cloud Scheduler
- `chameleon-dataplatform-dbt` — independent staging keys-only cleanup

> **Coverage needs no new infra, env, secret, or IAM** — it's a pure read-side composition
> of the registry + policy + discovery. It ships automatically with the Key Vault deploy
> (step 4) and the Console deploy (step 6). Nothing to configure; just verify (step 7).

> Do these in order. Steps 1 and 6 are independent and can be done any time.

---

## 0. Prerequisites
- `gcloud` authed to the target project (`your-gcp-project-id` or `your-gcp-project-id`).
- Terraform initialized in `chameleon-infra-gcp` for the target workspace/backend.
- A strong shared secret generated for the write token, e.g.: `openssl rand -hex 32`.
- Decide the target env: **dev** or **prod** (secret/scheduler names are suffixed with it).

---

## 1. dbt staging cleanup (independent — no service redeploy)
Makes `stg_users` keys-only (PII stays in `raw_users`).

```bash
cd chameleon-dataplatform-dbt
./.venv/bin/dbt build --select stg_users+        # NOT the fusion dbt on PATH
```
Verify no PII columns remain:
```bash
bq query --use_legacy_sql=false \
'SELECT column_name FROM `your-gcp-project-id`.chameleon_dev.INFORMATION_SCHEMA.COLUMNS
 WHERE table_name = "stg_users" ORDER BY ordinal_position'
```
Expect: `tenant_id, user_id, encryption_version, key_id, operation_id, ingested_at, source_system`
(no `email_token`, `encrypted_pii`, `data_hash`). Commit + push if dbt runs from git/CI.

---

## 2. Infra — `terraform apply` (`chameleon-infra-gcp`)
Provisions: the write-token Secret Manager secret, `compliance` dataset editor IAM for the
audit mirror, Key Vault Cloud Run env vars, the Cloud Scheduler crawl job, and the
`cloudscheduler` API.

```bash
cd chameleon-infra-gcp
# enable_pii_ingestor_worker MUST be true for the crawl endpoint + scheduler to exist.
terraform plan  -var 'enable_pii_ingestor_worker=true'   # review
terraform apply -var 'enable_pii_ingestor_worker=true'
```
Optional override: `-var 'warehouse_crawl_schedule=0 6 * * *'` (default = daily 06:00 UTC).

New resources to expect in the plan:
- `google_secret_manager_secret.pii_registry_write_token` (+ version + accessor IAM)
- `google_bigquery_dataset_iam_member.key_vault_compliance_editor`
- `google_cloud_scheduler_job.warehouse_metadata_crawl`
- `google_project_service.cloudscheduler`
- Key Vault Cloud Run env: `PII_REGISTRY_WRITE_TOKEN`, `PII_AUDIT_DATASET_ID`

---

## 3. Set the real write token (both sides must match)
The Terraform version is a **placeholder** — set the real value, then wire the same value
into the Console (Vercel).

```bash
# a) Key Vault side — add the real secret version
printf '%s' "$WRITE_TOKEN" | \
  gcloud secrets versions add pii-registry-write-token-dev --data-file=- \
  --project your-gcp-project-id

# b) Console side — Vercel runtime env (NOT in git/terraform)
cd chameleon-console
vercel env add VAULT_REGISTRY_WRITE_TOKEN production   # paste the SAME $WRITE_TOKEN
```
> If the tokens don't match, every declare returns **401**. If either is unset, declares
> return **503** (writes are disabled by default — this is the safe fallback).

---

## 4. Deploy Key Vault (`chameleon-key-vault`)
Picks up the new env vars + serves the declare, discovery, and coverage endpoints. Deploy
via the repo's normal CD (push to `main` → GitHub Actions) or manually redeploy the Cloud
Run revision. Commit the code first (currently uncommitted).

Endpoints added: `POST/PUT/DELETE /pii-registry/resources`, `GET /pii-registry/discovery`,
`GET /pii-registry/coverage` (coverage needs no config — read-only composition).

---

## 5. Deploy the pipelines worker (`chameleon-data-pipelines`)
Adds `POST /api/v1/warehouse-crawl` (the Cloud Scheduler target). Deploy via the repo's
CD (GitHub Actions → `pii-ingestor-worker`) or `gcloud run deploy`. Commit first.

---

## 6. Deploy the Console (`chameleon-console`)
Not connected to GitHub in Vercel — deploy manually:
```bash
cd chameleon-console
vercel --prod
```

---

## 7. Post-deploy verification

**Declare API (gated):**
```bash
# 401 without token
curl -s -o /dev/null -w '%{http_code}\n' -X POST "$KV_URL/pii-registry/resources"
# 201 with token
curl -s -X POST "$KV_URL/pii-registry/resources" \
  -H "Authorization: Bearer $WRITE_TOKEN" -H "x-tenant-id: default-tenant" \
  -H 'Content-Type: application/json' \
  -d '{"resourceId":"bigquery:acme.demo.contacts","system":"bigquery","resourceLayer":"RAW",
       "tenantIdColumn":"tenant_id","userIdColumn":"user_id",
       "piiFields":[{"name":"email","classification":"DIRECT_IDENTIFIER","handling":"ENCRYPT"}]}'
```
Then confirm it appears in the Console **Registry** page, and in Firestore
(`pii_registry_declarations`) + `compliance.pii_metadata_registry`.

**Crawler + discovery loop:**
```bash
# Trigger a crawl on demand (or wait for the daily schedule)
gcloud scheduler jobs run chameleon-warehouse-crawl-dev --location <region> \
  --project your-gcp-project-id
# Then check the discovery queue
curl -s "$KV_URL/pii-registry/discovery" -H "x-tenant-id: default-tenant"
```
Expect undeclared tables to appear; the Console Registry banner shows
"N discovered tables not yet declared". Declaring one removes it from the queue.

**Coverage score + gauge:**
```bash
curl -s "$KV_URL/pii-registry/coverage" -H "x-tenant-id: default-tenant"
```
Expect `{ score, counts:{protected,partial,exposed,total}, weights, items }`. The Console
**Overview** page shows the coverage gauge (ring + PROTECTED/PARTIAL/EXPOSED buckets, each
linking to its drill-down). Sanity check: the score should **drop** when the crawler finds
an undeclared table (EXPOSED) and **rise** after you declare it — same tenant end-to-end.

---

## Environment variable reference

| Service | Var | Value | Source |
|---|---|---|---|
| Key Vault | `PII_REGISTRY_WRITE_TOKEN` | shared secret | Secret Manager `pii-registry-write-token-<env>` |
| Key Vault | `PII_AUDIT_DATASET_ID` | `compliance` | terraform (enables BQ audit mirror) |
| Key Vault | `FIRESTORE_PII_DECLARATION_COLLECTION` | `pii_registry_declarations` | optional, has default |
| Console (Vercel) | `VAULT_REGISTRY_WRITE_TOKEN` | same shared secret | `vercel env` |
| Pipelines | `WAREHOUSE_DISCOVERY_DATASETS` | e.g. `chameleon_dev` | crawler scope (comma-separated) |
| Terraform | `enable_pii_ingestor_worker` | `true` | required for crawl endpoint + scheduler |
| Terraform | `warehouse_crawl_schedule` | `0 6 * * *` | crawl cron (optional) |

## Rollback
- **Declares:** unset `PII_REGISTRY_WRITE_TOKEN` on Key Vault → writes 503; reads unaffected.
- **Crawler:** pause with `gcloud scheduler jobs pause chameleon-warehouse-crawl-<env>`.
- Firestore declarations and audit-mirror rows are additive; removing a declaration via
  `DELETE /pii-registry/resources/:id` is the clean undo (writes a DEPRECATED mirror row).
