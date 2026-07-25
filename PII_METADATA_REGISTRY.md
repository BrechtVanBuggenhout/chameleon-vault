# PII Metadata Registry & Ghost Data Plan

**Date:** June 16, 2026
**Owner split:** Key Vault owns metadata contracts, lineage audit, deletion state, and certificate evidence. Pipelines owns warehouse scans, dbt integration, and high-volume data-plane execution. Infra owns tables, IAM, Pub/Sub, and cross-project access.

## Why This Exists

Project Chameleon needs a single source of truth for where PII can live and how each location should be handled during ingestion, discovery, deletion, and audit. Without this registry, ghost-data scanning, dbt controls, cross-project BigQuery handling, and certificates will each invent their own partial model.

## Registry MVP

The Key Vault now exposes the first control-plane slice as a typed in-process registry:

- `src/types/pii-registry.ts` defines the registry contract.
- `src/data/pii-registry.ts` seeds dev BigQuery/SaaS resources without raw PII.
- `src/services/pii-registry-service.ts` evaluates registry policy.
- `GET /pii-registry/resources` lists registry resources.
- `GET /pii-registry/resources/:resourceId` returns one resource plus policy evaluation.
- `GET /pii-registry/policy` returns aggregate policy status for dbt/demo clients.

This is still intentionally file-backed. The model is shaped so infra can later move it into managed storage without changing the consumer contract.

Start with a structured registry entry per table, file prefix, log sink, SaaS object, or external warehouse object.

```json
{
  "registryVersion": "2026-06-16",
  "resourceId": "bigquery:your-gcp-project-id.chameleon_dev.stg_users",
  "system": "bigquery",
  "resourceLayer": "STAGING",
  "visibility": "CUSTOMER_FACING",
  "tenantIdColumn": "tenant_id",
  "userIdColumn": "user_id",
  "piiColumns": [
    {
      "name": "email",
      "classification": "DIRECT_IDENTIFIER",
      "handling": "ENCRYPT",
      "requiredInMart": false
    }
  ],
  "lineageDestination": "bigquery:chameleon_dev.stg_users",
  "deletionStrategy": "CRYPTO_SHRED",
  "ghostDataScan": {
    "enabled": true,
    "scanMode": "SAMPLED",
    "patterns": ["EMAIL", "PHONE"]
  }
}
```

## Core Concepts

- **Resource ID:** Stable identifier for a data location. Prefer URI-like values such as `bigquery:project.dataset.table`, `gcs:bucket/prefix`, or `log:project/sink`.
- **Resource layer:** Warehouse resources should identify whether they are `RAW`, `STAGING`, `INTERMEDIATE`, or `MART`; SaaS resources can use `SAAS`.
- **Visibility:** `CUSTOMER_FACING` resources carry authored policy metadata for demos and dbt validation. `INTERNAL` resources represent implementation-owned data locations such as encrypted raw ingestion tables.
- **Tenant scope:** Every warehouse-facing resource should define how tenant scope is represented. For BigQuery this should be `tenant_id`.
- **Identity link:** Every user-level resource should define `user_id` or explain why user-level erasure does not apply.
- **PII columns:** Declared columns or fields expected to contain PII.
- **Handling:** `ENCRYPT`, `TOKENIZE`, `REDACT`, `HASH_SURROGATE`, `ALLOW_AGGREGATE_ONLY`, or `MANUAL_REVIEW`.
- **Deletion strategy:** `CRYPTO_SHRED`, `DELETE_ROWS`, `REDACT_FIELDS`, `EXTERNAL_WIPE`, or `MANUAL_REVIEW`.

## Ghost Data MVP

Ghost data is PII discovered somewhere that is not already covered by the expected registry/lineage path.

## Warehouse Metadata Discovery MVP

The current registry and scanner flow handles configured resources. The next product step is a warehouse metadata crawler that discovers BigQuery datasets, tables, and columns before row sampling starts. This is the feature required before public copy can safely say Chameleon "maps every table and column automatically."

Initial discovery behavior:

1. Pipelines queries BigQuery `INFORMATION_SCHEMA.TABLES` and `INFORMATION_SCHEMA.COLUMNS` for approved datasets.
2. Pipelines normalizes each table to `bigquery:project.dataset.table` and each column to `{ name, dataType, mode, ordinalPosition }`.
3. Pipelines compares discovered tables and columns against `GET /pii-registry/resources?system=bigquery`.
4. Pipelines produces three inventories:
   - registered assets: table exists in the registry and discovered metadata matches expected columns.
   - unregistered assets: table exists in the warehouse but not in the registry.
   - drifted assets: table exists in both places but has new, missing, or type-changed columns.
5. Unregistered or drifted assets become scan candidates only when they are inside an approved dataset scope.
6. Pipelines emits metadata-only lineage events to Key Vault. Never include sampled values or raw PII.

Recommended lineage event shape for discovery:

```json
{
  "eventType": "WAREHOUSE_METADATA_DISCOVERED",
  "dataClassification": "METADATA",
  "userId": "UNKNOWN",
  "source": "bigquery_metadata_crawler",
  "destination": "bigquery:project.dataset.table",
  "operationId": "metadata-crawl:project.dataset.table",
  "context": {
    "resource_id": "bigquery:project.dataset.table",
    "system": "bigquery",
    "dataset": "dataset",
    "table": "table",
    "registered": false,
    "column_count": 12,
    "columns": [
      {
        "name": "email",
        "data_type": "STRING",
        "mode": "NULLABLE",
        "ordinal_position": 3,
        "registry_status": "UNREGISTERED"
      }
    ],
    "recommended_action": "register_resource_or_exclude_dataset"
  }
}
```

The Key Vault lineage endpoint already accepts this as a resource-level event because `userId` is `UNKNOWN`. It must remain audit evidence and must not update the user-level Firestore hot path used by Janitor.

Initial scanner behavior:

1. Pipelines scans configured BigQuery tables and GCS/log locations.
2. Findings are normalized to tenant/user scope where possible.
3. Pipelines emits a Key Vault lineage event with:
   - `dataClassification` / `data_classification`: `GHOST_DATA` for discovered ghost findings, or `PII` for normal pipeline PII provisioning events.
   - `source`: scanner name, for example `ghost-data-scanner`
   - `destination`: resource ID, for example `bigquery:project.dataset.table`
   - `context` or `metadata`: match type, column/path, confidence, sample hash only, and recommended action.
4. Key Vault includes these events in deletion plans and later certificates.

Never send raw PII in the lineage event. Use hashes, column names, resource IDs, and confidence metadata only.

Scanner findings can be user-linked or resource-level:

- Use the actual `userId` / `user_id` only when the scanner can confidently map a finding to a user.
- Use `user_id: "UNKNOWN"` for table/column/resource-level findings that cannot be tied to one user.
- Key Vault records `UNKNOWN` resource-level `GHOST_DATA` findings in lineage audit, but does not add them to the Firestore user hot path used by Janitor.

## dbt Integration

dbt should consume the registry as policy, not duplicate it in model comments.

Pipelines now owns the internal encrypted raw ingestion table, currently modeled as `bigquery:your-gcp-project-id.chameleon_dev.raw_users` with `resourceLayer: RAW` and `visibility: INTERNAL`. dbt owns the customer-facing warehouse resources derived from it: `stg_users`, `int_customer_activity`, and `mart_customer_metrics`.

Initial dbt rules:

- `raw_users` is not part of the default ghost-scan scope unless raw-table scanning is explicitly enabled later.
- `stg_` models may expose encrypted/tokenized PII needed for operational transformations.
- `int_` models should join on `tenant_id`, `user_id`, or stable surrogate hashes.
- `mart_` models must not contain direct identifiers unless explicitly approved in the registry.
- Tests should fail if `tenant_id` is missing from tenant-scoped models.
- Tests should fail if a direct PII column appears in a mart without `handling: ALLOW_AGGREGATE_ONLY` or equivalent approval.

## Certificate v2 Impact

Future certificate claims should include a compact evidence summary:

```json
{
  "ghostDataSummary": [
    {
      "resourceId": "bigquery:project.dataset.table",
      "status": "MANUAL_REVIEW",
      "findingCount": 3,
      "lastSeen": "2026-06-16T00:00:00.000Z"
    }
  ],
  "warehouseCleanupStatus": "PARTIAL"
}
```

## Next Implementation Order

1. Define registry schema in Key Vault and check in an initial registry file for dev BigQuery/SaaS resources. **Done.**
2. Have pipelines consume `GET /pii-registry/resources?system=bigquery&scanEnabled=true` for scanner scope. **Done in pipelines MVP.**
3. Add a BigQuery metadata crawler in pipelines for approved datasets.
4. Compare discovered tables/columns against the registry and classify registered, unregistered, and drifted assets.
5. Emit `WAREHOUSE_METADATA_DISCOVERED` lineage events to Key Vault for inventory evidence.
6. Feed unregistered/drifted but approved assets into ghost-data scan candidates.
7. Add infra support for managed discovery inventory tables, scheduler/runtime, and narrow IAM if file/API-only evidence becomes too brittle.
8. Add dbt tests that enforce the registry rules across marts, backed by `GET /pii-registry/policy`.
