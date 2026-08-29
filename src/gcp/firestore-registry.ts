import { Firestore, FieldValue } from '@google-cloud/firestore';
import { KeyStatus } from '../types/index.js';
import { createLogger } from '../logging/index.js';

const logger = createLogger('firestore-registry');

export interface KeyMetadata {
  userId: string;
  deks: { [keyVersionId: string]: string }; // DEKs stored as base64 strings
  activeDekId: string | null; // ID of the currently active DEK, can be null if not set
  status: 'ACTIVE' | 'ROTATED' | 'SHREDDED' | 'DELETED';
  createdAt: Date;
  shredAt?: Date;
  rotatedAt?: Date;
  encryptionVersion: string; // e.g., 'v1' for deterministic, 'v2' for randomized
  tokenization?: {
    algorithm: string; // e.g., 'HMAC-SHA256'
    tokenKeyId: string; // ID of the key used for tokenization
  };
  deletionRequestId?: string; // Link to the active deletion request
  destinations?: string[]; // Hot-path lineage tracking
}

export class FirestoreRegistry {
  private db: Firestore;
  private collectionName: string;

  constructor(projectId: string, collectionName: string, databaseId?: string) {
    // databaseId is optional, so only pass if provided
    this.db = new Firestore({ projectId, ...(databaseId && { databaseId }) });
    this.collectionName = collectionName;
  }

  private getDocId(tenantId: string, userId: string): string {
    return `${tenantId}:${userId}`;
  }

  async getKeyForUser(userId: string, tenantId: string = 'default-tenant', keyVersionId?: string): Promise<{ encryptedDek: Buffer | null; activeDekId: string; encryptionVersion: string } | null> {
    try {
      const docId = this.getDocId(tenantId, userId);
      const doc = await this.db
        .collection(this.collectionName)
        .doc(docId)
        .get();

      if (!doc.exists) {
        logger.debug({ userId }, 'Key not found for user');
        return null;
      }

      const data = doc.data() as KeyMetadata;

      if (data.status === 'SHREDDED' || data.status === 'DELETED' || Object.keys(data.deks).length === 0) {
        logger.warn({ userId }, 'Attempted to access shredded key');
        return null;
      }

      const targetDekId = keyVersionId || data.activeDekId;
      if (!targetDekId) { // targetDekId can now be string | null
        logger.error({ userId }, 'No active DEK ID found for user');
        return null;
      }

      const dekBase64 = data.deks[targetDekId];
      if (!dekBase64) {
        logger.error({ userId, targetDekId }, 'DEK version not found for user');
        return null;
      }

      return {
        encryptedDek: Buffer.from(dekBase64, 'base64'),
        activeDekId: data.activeDekId!,
        encryptionVersion: data.encryptionVersion || 'v1',
      };
    } catch (error) {
      logger.error({ error, userId }, 'Failed to get key from Firestore');
      throw error;
    }
  }
  async setKeyForUser(
    userId: string,
    dek: Buffer,
    tenantId: string = 'default-tenant'
  ): Promise<void> {
    try {
      const docId = this.getDocId(tenantId, userId);
      const metadata: KeyMetadata = {
        userId, // We keep the original userId in the metadata
        deks: { v1: dek.toString('base64') }, // Store as base64, initial version 'v1'
        activeDekId: 'v1',
        status: 'ACTIVE',
        createdAt: new Date(),
        encryptionVersion: 'v2',
        tokenization: { algorithm: 'HMAC-SHA256', tokenKeyId: 'chameleon-token-key-v1' },
      };

      await this.db
        .collection(this.collectionName)
        .doc(docId)
        .set(metadata, { merge: false });

      logger.info({ userId, tenantId }, 'Key set for user with tenant isolation');
    } catch (error) {
      logger.error({ error, userId }, 'Failed to set key in Firestore');
      throw error;
    }
  }

  async rotateKeyForUser(userId: string, newDek: Buffer, tenantId: string = 'default-tenant'): Promise<string> {
    try {
      const docId = this.getDocId(tenantId, userId);
      const docRef = this.db.collection(this.collectionName).doc(docId);
      const doc = await docRef.get();

      if (!doc.exists) {
        throw new Error('User key not found for rotation');
      }

      const data = doc.data() as KeyMetadata;
      if (data.status === 'SHREDDED' || data.activeDekId === null) { // Also check if activeDekId is null
        throw new Error('Cannot rotate a shredded key');
      }

      const newVersionId = `v${Object.keys(data.deks).length + 1}`;
      const updatedDeks = { ...data.deks, [newVersionId]: newDek.toString('base64') };

      const update: Partial<KeyMetadata> = {
        deks: updatedDeks,
        activeDekId: newVersionId,
        status: 'ACTIVE', // Status remains active, rotatedAt tracks the event
        rotatedAt: new Date(),
      };

      await docRef.update(update);
      logger.info({ userId, tenantId, newVersionId }, 'Key rotated for user');
      return newVersionId;
    } catch (error) {
      logger.error({ error, userId }, 'Failed to rotate key in Firestore');
      throw error;
    }
  }

  async shredKeyForUser(userId: string, tenantId: string = 'default-tenant', deletionRequestId?: string): Promise<void> {
    try {
      const docId = this.getDocId(tenantId, userId);
      // Instead of just setting status, we remove the DEK material
      const update: Partial<KeyMetadata> = {
        deks: {}, // Irreversible removal of DEK material
        activeDekId: null,
        status: 'SHREDDED', // Consistent with API_SPECIFICATION.md
        shredAt: new Date(),
      };

      if (deletionRequestId) update.deletionRequestId = deletionRequestId;

      // Use set+merge so deletion works even if the user never had an active key
      // (e.g. demo users or users whose data arrived via bulk load rather than
      // the ingestor). A missing key document still represents shredded state.
      await this.db
        .collection(this.collectionName)
        .doc(docId)
        .set(update, { merge: true });

      logger.info({ userId, deletionRequestId }, 'Key destroyed for user (DEK material removed)');
    } catch (error) {
      logger.error({ error, userId }, 'Failed to shred key in Firestore');
      throw error;
    }
  }

  // Deliberately separate from getKeyStatus/getKeyForUser below, even though
  // it overlaps with them -- this is the one function an outside auditor's
  // trust in the erasure claim ultimately rests on, so it's kept small and
  // legible on its own rather than layered on top of logic that also serves
  // unrelated purposes (decryption context, detailed status timestamps) and
  // could change for reasons that have nothing to do with this guarantee.
  // Returns false for a document that never existed at all -- no key was
  // ever generated, so there's nothing to have leaked either way, and that's
  // the correct answer to "is there currently recoverable key material."
  async hasActiveKeyMaterial(userId: string, tenantId: string = 'default-tenant'): Promise<boolean> {
    const docId = this.getDocId(tenantId, userId);
    const doc = await this.db.collection(this.collectionName).doc(docId).get();
    if (!doc.exists) {
      return false;
    }
    const data = doc.data() as KeyMetadata;
    return (data.status === 'ACTIVE' || data.status === 'ROTATED') && Object.keys(data.deks || {}).length > 0;
  }

  async getKeyStatus(userId: string, tenantId: string = 'default-tenant'): Promise<KeyStatus | null> {
    try {
      const docId = this.getDocId(tenantId, userId);
      const doc = await this.db
        .collection(this.collectionName)
        .doc(docId)
        .get();

      if (!doc.exists) {
        return null;
      }

      const data = doc.data() as KeyMetadata;

      const toIso = (val: unknown): string | undefined => {
        if (!val) return undefined;
        if (typeof (val as { toDate?: () => Date }).toDate === 'function') {
          return (val as { toDate: () => Date }).toDate().toISOString();
        }
        if (typeof (val as { toISOString?: () => string }).toISOString === 'function') {
          return (val as { toISOString: () => string }).toISOString();
        }
        return undefined;
      };

      return {
        status: data.status,
        created_at: toIso(data.createdAt) || new Date().toISOString(),
        shred_at: toIso(data.shredAt),
        rotated_at: toIso(data.rotatedAt),
        active_dek_id: data.activeDekId ?? undefined,
        activeDekId: data.activeDekId ?? undefined, // Add camelCase alias
        destinations: data.destinations,
      };
    } catch (error) {
      logger.error({ error, userId }, 'Failed to get key status from Firestore');
      throw error;
    }
  }

  /**
   * Hot-path: Track data destinations directly in the key registry.
   * This allows the Janitor to build cleanup plans without querying BigQuery.
   */
  async addDestinationToUser(userId: string, destination: string, tenantId: string = 'default-tenant'): Promise<void> {
    try {
      const docId = this.getDocId(tenantId, userId);
      await this.db.collection(this.collectionName).doc(docId).update({
        destinations: FieldValue.arrayUnion(destination)
      });
    } catch (error) {
      logger.error({ error, userId, destination }, 'Failed to update user destinations in Firestore');
      // We don't throw here as this is a non-critical side effect of the lineage route
    }
  }
}
