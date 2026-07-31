import { Firestore, Timestamp, CollectionReference, DocumentData } from '@google-cloud/firestore';
import { CertificateChainState } from '../types/certificate-chain.js';
import { createLogger } from '../logging/index.js';

const logger = createLogger('certificate-chain-repository');

export interface ChainSignResult {
  certificate: string;
  certificateHash: string;
}

export class CertificateChainRepository {
  private db: Firestore;
  private collectionName: string;

  constructor(projectId: string, collectionName: string, databaseId?: string) {
    this.db = new Firestore({ projectId, ...(databaseId && { databaseId }) });
    this.collectionName = collectionName;
  }

  private get collection(): CollectionReference<DocumentData> {
    return this.db.collection(this.collectionName);
  }

  /**
   * Atomically reserves the next slot in a tenant's certificate hash chain,
   * runs `sign` with the reserved previous-hash/sequence, then commits the
   * new chain head -- all inside one Firestore transaction, so two
   * deletions completing for the same tenant at once can never produce two
   * certificates claiming the same sequence number or previous hash.
   *
   * `sign` calls out to KMS, so it may run more than once if the
   * transaction retries due to contention (Firestore retries the whole
   * callback, re-reading first) -- only the winning attempt's certificate
   * is ever returned or persisted. Acceptable here: certificate signing has
   * no side effects that matter if discarded, and contention is rare for
   * this write pattern (one document per tenant, deletions completing
   * concurrently for the *same* tenant).
   */
  async appendToChain(
    tenantId: string,
    deletionRequestId: string,
    sign: (previousHash: string | null, sequence: number) => Promise<ChainSignResult>
  ): Promise<ChainSignResult & { previousHash: string | null; sequence: number }> {
    const docRef = this.collection.doc(tenantId);

    return this.db.runTransaction(async (transaction) => {
      const doc = await transaction.get(docRef);
      const current = doc.exists ? (doc.data() as CertificateChainState) : null;
      const previousHash = current?.last_hash ?? null;
      const sequence = (current?.sequence ?? 0) + 1;

      const result = await sign(previousHash, sequence);

      const nextState: CertificateChainState = {
        tenant_id: tenantId,
        sequence,
        last_hash: result.certificateHash,
        last_deletion_request_id: deletionRequestId,
        updated_at: Timestamp.now().toDate(),
      };
      transaction.set(docRef, nextState);

      logger.info({ tenantId, deletionRequestId, sequence }, 'Appended certificate to chain');
      return { ...result, previousHash, sequence };
    });
  }
}
