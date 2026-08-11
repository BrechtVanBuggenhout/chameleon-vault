import { Firestore, Timestamp, CollectionReference, DocumentData } from '@google-cloud/firestore';
import { AnalystAccess } from '../types/analyst-access.js';
import { createLogger } from '../logging/index.js';

const logger = createLogger('analyst-access-repository');

export class AnalystAccessRepository {
  private db: Firestore;
  private collectionName: string;

  constructor(projectId: string, collectionName: string, databaseId?: string) {
    this.db = new Firestore({ projectId, ...(databaseId && { databaseId }) });
    this.collectionName = collectionName;
  }

  private get collection(): CollectionReference<DocumentData> {
    return this.db.collection(this.collectionName);
  }

  async createClaim(
    tenantId: string,
    analystEmail: string,
    claimTokenHash: string,
    expiresAt: Date
  ): Promise<void> {
    const now = Timestamp.now().toDate();
    const record: AnalystAccess = {
      claim_token_hash: claimTokenHash,
      tenant_id: tenantId,
      analyst_email: analystEmail,
      created_at: now,
      expires_at: expiresAt,
    };
    await this.collection.doc(claimTokenHash).set(record);
    logger.info({ tenantId, analystEmail }, 'Created analyst claim');
  }

  async getClaimByTokenHash(claimTokenHash: string): Promise<AnalystAccess | null> {
    const doc = await this.collection.doc(claimTokenHash).get();
    if (!doc.exists) {
      return null;
    }
    return doc.data() as AnalystAccess;
  }

  // Marks the claim consumed and stores the issued credential's hash, but
  // only if it's still unclaimed -- a Firestore transaction closes the race
  // where two requests hit the same one-time link at once (e.g. an email
  // security scanner's prefetch racing the real click).
  async claimAndIssueCredential(claimTokenHash: string, credentialKeyHash: string): Promise<AnalystAccess | null> {
    const docRef = this.collection.doc(claimTokenHash);

    return this.db.runTransaction(async (transaction) => {
      const doc = await transaction.get(docRef);
      if (!doc.exists) {
        return null;
      }

      const record = doc.data() as AnalystAccess;
      if (record.claimed_at) {
        return null;
      }

      const claimedAt = Timestamp.now().toDate();
      transaction.update(docRef, { claimed_at: claimedAt, credential_key_hash: credentialKeyHash });
      return { ...record, claimed_at: claimedAt, credential_key_hash: credentialKeyHash };
    });
  }

  // Console-session credentials skip the claim step entirely -- there's no
  // separate token to hand out and later consume, so the record is created
  // already "claimed", keyed by the credential's own hash rather than a
  // claim_token_hash (reused here as the doc id since nothing else reads
  // claim_token_hash as a semantic field -- it's only ever used as a
  // Firestore key, same as in createClaim above).
  async createSessionCredential(
    tenantId: string,
    analystEmail: string,
    credentialKeyHash: string,
    credentialExpiresAt: Date
  ): Promise<void> {
    const now = Timestamp.now().toDate();
    const record: AnalystAccess = {
      claim_token_hash: credentialKeyHash,
      credential_key_hash: credentialKeyHash,
      tenant_id: tenantId,
      analyst_email: analystEmail,
      created_at: now,
      expires_at: credentialExpiresAt,
      claimed_at: now,
      source: 'console_session',
      credential_expires_at: credentialExpiresAt,
    };
    await this.collection.doc(credentialKeyHash).set(record);
    logger.info({ tenantId, analystEmail }, 'Minted console-session analyst credential');
  }

  async resolveCredential(credentialKeyHash: string): Promise<AnalystAccess | null> {
    const snapshot = await this.collection
      .where('credential_key_hash', '==', credentialKeyHash)
      .limit(1)
      .get();

    if (snapshot.empty) {
      return null;
    }
    return snapshot.docs[0].data() as AnalystAccess;
  }
}
