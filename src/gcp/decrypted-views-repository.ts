import { Firestore, Timestamp, CollectionReference, DocumentData } from '@google-cloud/firestore';
import { DecryptedViewDeclaration } from '../types/decrypted-view.js';
import { createLogger } from '../logging/index.js';

const logger = createLogger('decrypted-views-repository');

export class DecryptedViewsRepository {
  private db: Firestore;
  private collectionName: string;

  constructor(projectId: string, collectionName: string, databaseId?: string) {
    this.db = new Firestore({ projectId, ...(databaseId && { databaseId }) });
    this.collectionName = collectionName;
  }

  private get collection(): CollectionReference<DocumentData> {
    return this.db.collection(this.collectionName);
  }

  // {tenantId}:{viewName} as the doc id -- same convention as user_keys'
  // {tenantId}:{userId} -- naturally enforces one view per name per tenant
  // without a separate uniqueness check.
  private docId(tenantId: string, viewName: string): string {
    return `${tenantId}:${viewName}`;
  }

  async create(
    declaration: Omit<DecryptedViewDeclaration, 'status' | 'created_at'>
  ): Promise<DecryptedViewDeclaration> {
    const docRef = this.collection.doc(this.docId(declaration.tenant_id, declaration.view_name));

    const existing = await docRef.get();
    if (existing.exists && (existing.data() as DecryptedViewDeclaration).status === 'active') {
      throw new Error(`Decrypted view "${declaration.view_name}" already exists for tenant ${declaration.tenant_id}`);
    }

    const record: DecryptedViewDeclaration = {
      ...declaration,
      status: 'active',
      created_at: Timestamp.now().toDate(),
    };
    await docRef.set(record);
    logger.info(
      { tenantId: declaration.tenant_id, viewName: declaration.view_name, createdBy: declaration.created_by },
      'Decrypted view declared'
    );
    return record;
  }

  async get(tenantId: string, viewName: string): Promise<DecryptedViewDeclaration | null> {
    const doc = await this.collection.doc(this.docId(tenantId, viewName)).get();
    if (!doc.exists) return null;
    return doc.data() as DecryptedViewDeclaration;
  }

  async listByTenant(tenantId: string): Promise<DecryptedViewDeclaration[]> {
    const snapshot = await this.collection.where('tenant_id', '==', tenantId).get();
    return snapshot.docs.map(doc => doc.data() as DecryptedViewDeclaration);
  }

  // Status flip, not a doc delete -- the record that this view existed, why,
  // and when it was revoked is itself part of the audit trail.
  async revoke(tenantId: string, viewName: string, revokedBy: string): Promise<DecryptedViewDeclaration | null> {
    const docRef = this.collection.doc(this.docId(tenantId, viewName));
    const doc = await docRef.get();
    if (!doc.exists) return null;

    const update = {
      status: 'revoked' as const,
      revoked_at: Timestamp.now().toDate(),
      revoked_by: revokedBy,
    };
    await docRef.update(update);
    logger.info({ tenantId, viewName, revokedBy }, 'Decrypted view revoked');
    return { ...(doc.data() as DecryptedViewDeclaration), ...update };
  }
}
