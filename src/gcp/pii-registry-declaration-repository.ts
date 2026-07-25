import { Firestore } from '@google-cloud/firestore';
import { createLogger } from '../logging/index.js';
import type { PiiDeclarationStore } from '../services/pii-registry-service.js';
import type { PiiRegistryEntry } from '../types/pii-registry.js';
import type { BigQueryPiiRegistryAuditMirror } from './pii-registry-audit-mirror.js';

const logger = createLogger('pii-registry-declaration-repository');

/**
 * Durable store for user-declared ("manual") PII registry entries, backed by Firestore.
 * One document per (tenant, resource). Implements PiiDeclarationStore so the
 * PiiRegistryService can write through it, and optionally fans out to a best-effort
 * BigQuery audit mirror after each durable write.
 */
export class FirestorePiiDeclarationRepository implements PiiDeclarationStore {
  private readonly db: Firestore;

  constructor(
    projectId: string,
    private readonly collectionName: string,
    databaseId?: string,
    private readonly auditMirror?: BigQueryPiiRegistryAuditMirror
  ) {
    // ignoreUndefinedProperties: declarations have optional fields (notes,
    // resourceLayer, tenant/user id columns); Firestore rejects `undefined`
    // values outright, which 500'd declares submitted without them.
    this.db = new Firestore({ projectId, ...(databaseId && { databaseId }), ignoreUndefinedProperties: true });
  }

  private docId(tenantId: string, resourceId: string): string {
    // resourceId can contain '/' (e.g. gcs:bucket/prefix); encode so it is a valid doc id.
    return `${tenantId}:${encodeURIComponent(resourceId)}`;
  }

  /** Loads every declaration across all tenants for boot-time composition. */
  async loadAll(): Promise<PiiRegistryEntry[]> {
    try {
      const snapshot = await this.db.collection(this.collectionName).get();
      const entries = snapshot.docs.map((doc) => doc.data() as PiiRegistryEntry);
      if (entries.length > 0) {
        logger.info({ count: entries.length }, 'Loaded manual PII declarations from Firestore');
      }
      return entries;
    } catch (error) {
      logger.warn({ error }, 'Failed to load manual PII declarations from Firestore; continuing without them');
      return [];
    }
  }

  async upsert(entry: PiiRegistryEntry): Promise<void> {
    if (!entry.tenantId) {
      throw new Error('Cannot persist a declaration without a tenantId.');
    }
    await this.db
      .collection(this.collectionName)
      .doc(this.docId(entry.tenantId, entry.resourceId))
      .set(entry, { merge: true });
    // Audit mirror is best-effort and must never block the durable write path.
    await this.auditMirror?.record(entry);
  }

  async delete(tenantId: string, resourceId: string): Promise<void> {
    await this.db.collection(this.collectionName).doc(this.docId(tenantId, resourceId)).delete();
    await this.auditMirror?.recordDeletion(tenantId, resourceId);
  }
}
