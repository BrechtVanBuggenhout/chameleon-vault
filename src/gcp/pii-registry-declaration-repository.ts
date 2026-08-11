import { FieldValue, Firestore } from '@google-cloud/firestore';
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
    // ignoreUndefinedProperties strips an undefined updatedAtColumn before
    // the write, and .set(..., {merge:true}) then leaves whatever was
    // already in Firestore untouched -- correct for lastSyncedAt (a normal
    // declare/update that doesn't mention it should never wipe it), but
    // wrong for updatedAtColumn itself: a customer clearing it in the
    // console must actually delete it, not silently keep the old value.
    // When it's being cleared, also delete lastSyncedAt, so a later
    // re-declare of the same column starts with a clean watermark rather
    // than resuming from a stale one.
    const payload: Record<string, unknown> = { ...entry };
    if (!entry.updatedAtColumn) {
      payload.updatedAtColumn = FieldValue.delete();
      payload.lastSyncedAt = FieldValue.delete();
    }
    // Same gotcha as updatedAtColumn above: ignoreUndefinedProperties strips
    // an undefined lastModifiedBy before the write, and merge:true then
    // leaves whatever's already stored untouched -- which would silently
    // keep attributing this write to whoever last had a real credential,
    // even when this call has none. Force it to actually clear.
    if (!entry.lastModifiedBy) {
      payload.lastModifiedBy = FieldValue.delete();
    }
    await this.db
      .collection(this.collectionName)
      .doc(this.docId(entry.tenantId, entry.resourceId))
      .set(payload, { merge: true });
    // Audit mirror is best-effort and must never block the durable write path.
    await this.auditMirror?.record(entry);
  }

  async delete(tenantId: string, resourceId: string): Promise<void> {
    await this.db.collection(this.collectionName).doc(this.docId(tenantId, resourceId)).delete();
    await this.auditMirror?.recordDeletion(tenantId, resourceId);
  }

  /**
   * Advances lastSyncedAt only if candidateIso is genuinely newer than
   * what's already stored -- plain last-write-wins would let an
   * overlapping daily-scheduler run and a manually-triggered Sync Now
   * regress the watermark (not data-unsafe given pii_vault_sync.py's own
   * per-user-per-field idempotency, but it would silently defeat the
   * incremental optimization on a recurring basis). Returns the resulting
   * stored value either way, so the caller's in-memory copy stays correct
   * even when this call's candidate was rejected.
   */
  async advanceSyncWatermark(tenantId: string, resourceId: string, candidateIso: string): Promise<string | undefined> {
    const docRef = this.db.collection(this.collectionName).doc(this.docId(tenantId, resourceId));
    return this.db.runTransaction(async (transaction) => {
      const snapshot = await transaction.get(docRef);
      if (!snapshot.exists) {
        throw new Error(`No declaration found for ${resourceId} (tenant ${tenantId}) to mark synced.`);
      }
      const current = (snapshot.data() as PiiRegistryEntry).lastSyncedAt;
      if (current && new Date(current).getTime() >= new Date(candidateIso).getTime()) {
        return current;
      }
      transaction.set(docRef, { lastSyncedAt: candidateIso }, { merge: true });
      return candidateIso;
    });
  }

  /**
   * Same monotonic-advance shape as advanceSyncWatermark, for the separate
   * lastSyncAttemptAt field -- advanced after *every* successful sync run
   * (full or incremental), unlike lastSyncedAt which only ever moves for a
   * resource with updatedAtColumn set. See PiiRegistryEntry.lastSyncAttemptAt.
   */
  async advanceLastSyncAttempt(tenantId: string, resourceId: string, candidateIso: string): Promise<string | undefined> {
    const docRef = this.db.collection(this.collectionName).doc(this.docId(tenantId, resourceId));
    return this.db.runTransaction(async (transaction) => {
      const snapshot = await transaction.get(docRef);
      if (!snapshot.exists) {
        throw new Error(`No declaration found for ${resourceId} (tenant ${tenantId}) to mark sync-attempted.`);
      }
      const current = (snapshot.data() as PiiRegistryEntry).lastSyncAttemptAt;
      if (current && new Date(current).getTime() >= new Date(candidateIso).getTime()) {
        return current;
      }
      transaction.set(docRef, { lastSyncAttemptAt: candidateIso }, { merge: true });
      return candidateIso;
    });
  }
}
