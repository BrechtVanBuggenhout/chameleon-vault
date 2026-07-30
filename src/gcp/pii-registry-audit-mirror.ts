import { BigQuery } from '@google-cloud/bigquery';
import { createLogger } from '../logging/index.js';
import type { PiiClassification, PiiRegistryEntry } from '../types/pii-registry.js';

const logger = createLogger('pii-registry-audit-mirror');

// Most→least sensitive; used to pick a representative resource-level classification
// for the flat mirror row (per-field detail is preserved in the metadata JSON column).
const CLASSIFICATION_SEVERITY: PiiClassification[] = [
  'DIRECT_IDENTIFIER',
  'SENSITIVE',
  'CONTACT',
  'QUASI_IDENTIFIER',
  'BEHAVIORAL',
  'SYSTEM_IDENTIFIER',
];

function representativeClassification(entry: PiiRegistryEntry): string {
  for (const classification of CLASSIFICATION_SEVERITY) {
    if (entry.piiFields.some((field) => field.classification === classification)) {
      return classification;
    }
  }
  return 'PII';
}

function representativeHandling(entry: PiiRegistryEntry): string {
  const handlings = new Set(entry.piiFields.map((field) => field.handling));
  return handlings.size === 1 ? [...handlings][0] : 'MIXED';
}

/**
 * Append-only audit mirror of user declarations into `compliance.pii_metadata_registry`.
 * This is evidence/analytics only — never the read path — so every failure is swallowed
 * and logged. Firestore remains the source of truth for declarations.
 */
export class BigQueryPiiRegistryAuditMirror {
  private readonly bq: BigQuery;

  constructor(
    projectId: string,
    private readonly datasetId: string,
    private readonly tableId = 'pii_metadata_registry'
  ) {
    this.bq = new BigQuery({ projectId });
  }

  async record(entry: PiiRegistryEntry): Promise<void> {
    if (!entry.tenantId) {
      return; // tenant_id is REQUIRED in the mirror table; manual entries always have one.
    }
    const nowIso = new Date().toISOString();
    const row = {
      tenant_id: entry.tenantId,
      resource_id: entry.resourceId,
      system: entry.system,
      classification: representativeClassification(entry),
      handling: representativeHandling(entry),
      deletion_strategy: entry.deletionStrategy,
      status: entry.status ?? 'PENDING_REVIEW',
      confidence: 1.0,
      owner: entry.ownerConnector,
      notes: entry.notes ?? null,
      metadata: JSON.stringify({
        resourceLayer: entry.resourceLayer,
        visibility: entry.visibility,
        tenantIdColumn: entry.tenantIdColumn,
        userIdColumn: entry.userIdColumn,
        ghostDataScan: entry.ghostDataScan,
        piiFields: entry.piiFields,
      }),
      created_at: entry.createdAt ?? nowIso,
      updated_at: entry.updatedAt ?? nowIso,
      last_seen_at: nowIso,
    };

    try {
      await this.bq.dataset(this.datasetId).table(this.tableId).insert([row]);
      logger.info({ resourceId: entry.resourceId, tenantId: entry.tenantId }, 'Mirrored declaration to compliance registry');
    } catch (error) {
      logger.warn({ error, resourceId: entry.resourceId }, 'Failed to mirror declaration to BigQuery audit table');
    }
  }

  /** Records a soft-delete marker row so the audit trail shows the removal. */
  async recordDeletion(tenantId: string, resourceId: string): Promise<void> {
    const nowIso = new Date().toISOString();
    const row = {
      tenant_id: tenantId,
      resource_id: resourceId,
      system: 'external',
      classification: 'PII',
      handling: 'MANUAL_REVIEW',
      deletion_strategy: 'MANUAL_REVIEW',
      status: 'DEPRECATED',
      confidence: null,
      owner: 'manual',
      notes: 'Declaration removed via Console.',
      metadata: JSON.stringify({ event: 'DECLARATION_REMOVED' }),
      created_at: nowIso,
      updated_at: nowIso,
      last_seen_at: nowIso,
    };
    try {
      await this.bq.dataset(this.datasetId).table(this.tableId).insert([row]);
    } catch (error) {
      logger.warn({ error, resourceId }, 'Failed to mirror declaration removal to BigQuery audit table');
    }
  }
}
