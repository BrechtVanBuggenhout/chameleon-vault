import { Firestore } from '@google-cloud/firestore';
import { KeyStatus } from '../types/index.js';
import { DeletionRequest } from '../types/deletion-request.js';

// A deliberately minimal, read-only Firestore client -- exactly the two
// reads the certificate-issuance decision needs (see sign.ts), nothing
// else. Not a reuse of FirestoreRegistry/DeletionRequestRepository (which
// carry write methods and other unrelated surface): the whole point of
// this module is a small, independently-reviewable trust boundary, and
// importing classes with a much larger surface than this actually needs
// would work against that. See chameleon-paper/TEE_ATTESTATION_PLAN.md.
export class CertificateSignerFirestoreClient {
  private db: Firestore;

  constructor(
    projectId: string,
    private readonly keyRegistryCollection: string,
    private readonly deletionRequestCollection: string,
    databaseId?: string
  ) {
    this.db = new Firestore({ projectId, ...(databaseId && { databaseId }) });
  }

  private getKeyDocId(tenantId: string, userId: string): string {
    return `${tenantId}:${userId}`;
  }

  private toIso(val: unknown): string | undefined {
    if (!val) return undefined;
    if (typeof (val as { toDate?: () => Date }).toDate === 'function') {
      return (val as { toDate: () => Date }).toDate().toISOString();
    }
    if (typeof (val as { toISOString?: () => string }).toISOString === 'function') {
      return (val as { toISOString: () => string }).toISOString();
    }
    return undefined;
  }

  async getKeyStatus(userId: string, tenantId: string = 'default-tenant'): Promise<KeyStatus | null> {
    const docId = this.getKeyDocId(tenantId, userId);
    const doc = await this.db.collection(this.keyRegistryCollection).doc(docId).get();
    if (!doc.exists) return null;

    const data = doc.data() as {
      status: KeyStatus['status'];
      createdAt?: unknown;
      shredAt?: unknown;
      rotatedAt?: unknown;
      activeDekId?: string;
      destinations?: string[];
    };

    const shredAt = this.toIso(data.shredAt);
    const rotatedAt = this.toIso(data.rotatedAt);

    return {
      status: data.status,
      created_at: this.toIso(data.createdAt) || new Date().toISOString(),
      // Both snake_case and camelCase set, deliberately -- the original
      // FirestoreRegistry.getKeyStatus (src/gcp/firestore-registry.ts) only
      // ever sets shred_at, never shredAt, even though the KeyStatus type
      // declares both. certificate-service.ts reads keyStatus.shredAt
      // (camelCase) when building a certificate's shredDate claim, so that
      // mismatch means every certificate's shredDate has silently been the
      // *issuance* time (the undefined-fallback), not the real shred time,
      // since RFC 3161/chain-hashing work landed. Not copying that bug into
      // new code. Fixing it in the original class too is a separate,
      // explicitly out-of-scope decision -- this extraction is meant to be
      // behavior-preserving for everything except this one new read path.
      shred_at: shredAt,
      shredAt,
      rotated_at: rotatedAt,
      rotatedAt,
      active_dek_id: data.activeDekId,
      activeDekId: data.activeDekId,
      destinations: data.destinations,
    };
  }

  async getDeletionRequest(deletionRequestId: string): Promise<DeletionRequest | null> {
    const doc = await this.db.collection(this.deletionRequestCollection).doc(deletionRequestId).get();
    if (!doc.exists) return null;
    return doc.data() as DeletionRequest;
  }

  async getLatestCompletedDeletionRequestForUser(userId: string, tenantId: string = 'default-tenant'): Promise<DeletionRequest | null> {
    const snapshot = await this.db
      .collection(this.deletionRequestCollection)
      .where('user_id', '==', userId)
      .where('tenant_id', '==', tenantId)
      .where('status', 'in', ['CASCADE_COMPLETE', 'CERTIFICATE_ISSUED'])
      .orderBy('created_at', 'desc')
      .limit(1)
      .get();

    if (snapshot.empty) return null;
    return snapshot.docs[0].data() as DeletionRequest;
  }
}
