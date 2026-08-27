import { Firestore, Timestamp, CollectionReference, DocumentData } from '@google-cloud/firestore';
import { CertificateChainState, CertificateChainEntry } from '../types/certificate-chain.js';
import { createLogger } from '../logging/index.js';
import { CHAIN_ANCHOR_MARKER } from '../logging/audit-anchor.js';

const logger = createLogger('certificate-chain-repository');

export interface ChainSignResult {
  certificate: string;
  certificateHash: string;
}

export class CertificateChainRepository {
  private db: Firestore;
  private collectionName: string;
  // Fixed, not configurable -- this index has no meaning outside the chain
  // state it's derived from, so it doesn't need its own env var.
  private readonly entryCollectionName = 'certificate_chain_entries';

  constructor(projectId: string, collectionName: string, databaseId?: string) {
    this.db = new Firestore({ projectId, ...(databaseId && { databaseId }) });
    this.collectionName = collectionName;
  }

  private get collection(): CollectionReference<DocumentData> {
    return this.db.collection(this.collectionName);
  }

  private get entryCollection(): CollectionReference<DocumentData> {
    return this.db.collection(this.entryCollectionName);
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

    const outcome = await this.db.runTransaction(async (transaction) => {
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

      // Indexed by the certificate's own hash, not by (tenant, sequence) --
      // see CertificateChainEntry for why. Written in the same transaction
      // as the chain head so the index can never point at a certificate the
      // chain doesn't actually agree was appended.
      const entry: CertificateChainEntry = {
        tenant_id: tenantId,
        sequence,
        previous_hash: previousHash,
        deletion_request_id: deletionRequestId,
        created_at: Timestamp.now().toDate(),
      };
      transaction.set(this.entryCollection.doc(result.certificateHash), entry);

      logger.info({ tenantId, deletionRequestId, sequence }, 'Appended certificate to chain');
      return { ...result, previousHash, sequence };
    });

    // Emitted after commit, outside the transaction (Cloud Logging isn't
    // transactional and doesn't need to be -- this is a best-effort external
    // anchor, not the source of truth). Structured JSON to stdout, which
    // Cloud Run ships to Cloud Logging with this parsed into jsonPayload;
    // the sink filter in chameleon-infra-gcp/audit_logging.tf matches on
    // the marker field and exports matches into the locked audit_logs
    // bucket, so even a later in-place rewrite of the Firestore chain
    // document above leaves this record intact and independently dated.
    logger.info(
      {
        [CHAIN_ANCHOR_MARKER]: true,
        auditEventType: 'certificate_chain_append',
        tenantId,
        deletionRequestId,
        sequence: outcome.sequence,
        hash: outcome.certificateHash,
        previousHash: outcome.previousHash,
      },
      'Certificate chain anchor'
    );

    return outcome;
  }

  // Public by design -- see CertificateChainEntry. Returns null rather than
  // throwing on a miss so the route can 404 cleanly.
  async getEntryByHash(certificateHash: string): Promise<CertificateChainEntry | null> {
    const doc = await this.entryCollection.doc(certificateHash).get();
    return doc.exists ? (doc.data() as CertificateChainEntry) : null;
  }
}
