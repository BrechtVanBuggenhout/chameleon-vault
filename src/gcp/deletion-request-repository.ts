import { Firestore, Timestamp, CollectionReference, DocumentData, FieldValue } from '@google-cloud/firestore';
import { DeletionRequest, DeletionRequestStatus } from '../types/deletion-request.js';
import { createLogger } from '../logging/index.js';

const logger = createLogger('deletion-request-repository');

export class DeletionRequestRepository {
  private db: Firestore;
  private collectionName: string;

  constructor(projectId: string, collectionName: string, databaseId?: string) {
    // databaseId is optional, so only pass if provided
    this.db = new Firestore({ projectId, ...(databaseId && { databaseId }) });
    this.collectionName = collectionName;
  }

  private get collection(): CollectionReference<DocumentData> {
    return this.db.collection(this.collectionName);
  }

  async createDeletionRequest(userId: string, operationId: string, tenantId: string = 'default-tenant'): Promise<DeletionRequest> {
    const docRef = this.collection.doc(operationId);

    return await this.db.runTransaction(async (transaction) => {
      const doc = await transaction.get(docRef);
      if (doc.exists) {
        logger.info({ userId, operationId }, 'Deletion request already exists, returning existing');
        return doc.data() as DeletionRequest;
      }

      const now = Timestamp.now();
      const newRequest: DeletionRequest = {
        deletion_request_id: operationId,
        tenant_id: tenantId,
        user_id: userId, // Internal representation uses snake_case
        status: 'SHRED_REQUESTED' as DeletionRequestStatus,
        created_at: now.toDate(),
        status_history: [{ status: 'SHRED_REQUESTED' as DeletionRequestStatus, timestamp: now.toDate() }],
        janitor_wipes: [],
      };

      transaction.set(docRef, newRequest);
      logger.info({ userId, tenantId, operationId, status: newRequest.status }, 'Created new deletion request');
      return newRequest;
    });
  }

  async getDeletionRequest(deletionRequestId: string): Promise<DeletionRequest | null> {
    const doc = await this.collection.doc(deletionRequestId).get();
    if (!doc.exists) {
      return null;
    }
    return doc.data() as DeletionRequest;
  }

  async getActiveDeletionRequestForUser(userId: string, tenantId: string = 'default-tenant'): Promise<DeletionRequest | null> {
    const snapshot = await this.collection
      .where('user_id', '==', userId)
      .where('tenant_id', '==', tenantId)
      .where('status', 'in', ['SHRED_REQUESTED', 'KEY_DESTROYED', 'CASCADE_PENDING', 'CASCADE_IN_PROGRESS', 'CASCADE_PARTIAL_FAILURE'])
      .orderBy('created_at', 'desc')
      .limit(1)
      .get();

    if (snapshot.empty) {
      return null;
    }
    return snapshot.docs[0].data() as DeletionRequest;
  }

  async updateDeletionRequestStatus(
    deletionRequestId: string,
    newStatus: DeletionRequestStatus,
    updateFields: Partial<DeletionRequest> = {},
  ): Promise<void> {
    const now = Timestamp.now();
    const updateData: any = {
      status: newStatus,
      status_history: FieldValue.arrayUnion({ status: newStatus, timestamp: now.toDate() }),
      ...updateFields,
    };

    await this.collection.doc(deletionRequestId).update(updateData);
    logger.info({ deletionRequestId, newStatus }, 'Updated deletion request status');
  }

  // Method to update janitor wipe status
  async updateJanitorWipeStatus(
    deletionRequestId: string, 
    destination: string, 
    status: 'PENDING' | 'IN_PROGRESS' | 'SUCCEEDED' | 'FAILED' | 'DLQ', 
    details?: Record<string, unknown>
  ): Promise<void> {
    const docRef = this.collection.doc(deletionRequestId);

    await this.db.runTransaction(async (transaction) => {
      const doc = await transaction.get(docRef);
      if (!doc.exists) {
        throw new Error(`Deletion request ${deletionRequestId} not found`);
      }

      const data = doc.data() as DeletionRequest;
      const wipes = data.janitor_wipes || [];
      const wipeIndex = wipes.findIndex(w => w.destination === destination);

      const wipeUpdate = {
        destination,
        status,
        updated_at: Timestamp.now().toDate(),
        details: details || {}
      };

      if (wipeIndex > -1) {
        wipes[wipeIndex] = { ...wipes[wipeIndex], ...wipeUpdate };
      } else {
        wipes.push(wipeUpdate);
      }

      transaction.update(docRef, { janitor_wipes: wipes });
    });

    logger.info({ deletionRequestId, destination, status }, 'Updated janitor wipe status in Firestore');
  }
}
