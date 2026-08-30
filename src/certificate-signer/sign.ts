import * as crypto from 'crypto';
import { SigningKmsClient } from './kms-client.js';
import { CertificateSignerFirestoreClient } from './firestore-client.js';
import { CertificateLineageItem, DestructionCertificateClaims, KeyStatus } from '../types/index.js';
import { DeletionRequest } from '../types/deletion-request.js';
import { GhostDataSummary } from '../types/lineage.js';
import { createLogger } from './logger.js';

const logger = createLogger('certificate-signer');

// Same duck-typing as the code this was extracted from -- Firestore's Node
// SDK reads timestamp fields back as its own Timestamp class, not a native
// Date; a plain Date also needs to work here (e.g. tests constructing
// janitor_wipes by hand), and only one of the two ever has toDate().
function timestampToIso(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  if (value && typeof (value as { toDate?: unknown }).toDate === 'function') {
    return (value as { toDate: () => Date }).toDate().toISOString();
  }
  return String(value);
}

function assertKeyShredded(userId: string, keyStatus: KeyStatus | null): asserts keyStatus is KeyStatus {
  if (!keyStatus || (keyStatus.status !== 'SHREDDED' && keyStatus.status !== 'DELETED')) {
    throw new Error(`Cannot generate certificate: Key for user ${userId} is not shredded.`);
  }
}

function assertCascadeComplete(userId: string, deletionRequest: DeletionRequest | null): asserts deletionRequest is DeletionRequest {
  if (!deletionRequest || (deletionRequest.status !== 'CASCADE_COMPLETE' && deletionRequest.status !== 'CERTIFICATE_ISSUED')) {
    throw new Error(`Cannot generate certificate: no completed deletion cascade found for user ${userId}`);
  }
}

export interface GenerateClaimsInput {
  userId: string;
  tenantId?: string;
  deletionRequestId?: string;
  // Pre-fetched by the caller (the orchestrator, chameleon-key-vault's
  // CertificateService), NOT re-fetched in here -- see the module-level
  // comment below for why this is safe to accept as a trusted parameter
  // when the deletion/key status above is not.
  ghostDataSummary: GhostDataSummary[];
  knownDestinationTypes: string[];
}

/**
 * The trust-critical certificate-issuance decision, extracted out of
 * CertificateService (chameleon-paper/TEE_ATTESTATION_PLAN.md, Phase 0 --
 * the prerequisite for eventually running this specific logic inside a GCP
 * Confidential Space TEE, so an outside auditor can verify the code that
 * decided to sign a certificate is exactly Chameleon's published source,
 * not a compromised or buggy deploy).
 *
 * The property this class exists to preserve: `generateClaims` independently
 * re-reads the deletion request's and key's real persisted Firestore state
 * itself, via its own CertificateSignerFirestoreClient -- it never accepts a
 * pre-computed "it's complete" claim from a caller. That's the actual thing
 * a future TEE attestation of this code would be attesting to; if a caller
 * could just hand this class a trusted boolean instead, moving it into an
 * enclave would prove nothing (a compromised orchestrator could still lie
 * about the input, and the enclave would honestly attest to that lie).
 *
 * ghostDataSummary and knownDestinationTypes ARE accepted as caller-supplied
 * parameters, deliberately -- this is not a concession on that boundary, it's
 * outside it: ghost-data findings are informational and explicitly
 * NOT_TRACKED/non-authoritative by design (see ghostDataScanCoverage below),
 * and knownDestinationTypes is a static, compile-time-fixed list. Neither is
 * part of "did we actually shred the key and complete the cascade."
 */
export class CertificateSigner {
  constructor(
    private readonly firestoreClient: CertificateSignerFirestoreClient,
    private readonly signingKmsClient: SigningKmsClient
  ) {}

  async generateClaims(input: GenerateClaimsInput): Promise<Omit<DestructionCertificateClaims, 'previousCertificateHash' | 'chainSequence'>> {
    const { userId, tenantId = 'default-tenant', deletionRequestId, ghostDataSummary, knownDestinationTypes } = input;
    logger.info({ userId, tenantId, deletionRequestId }, 'Generating destruction certificate claims');

    const keyStatus = await this.firestoreClient.getKeyStatus(userId, tenantId);
    const deletionRequest = deletionRequestId
      ? await this.firestoreClient.getDeletionRequest(deletionRequestId)
      : await this.firestoreClient.getLatestCompletedDeletionRequestForUser(userId, tenantId);

    assertKeyShredded(userId, keyStatus);
    assertCascadeComplete(userId, deletionRequest);

    // Only ever built from real, recorded outcomes -- never re-derived from
    // raw lineage/destination-name data. Filtering to SUCCEEDED is
    // defensive, not load-bearing: CASCADE_COMPLETE is only reachable when
    // every wipe succeeded, so a FAILED entry here should never actually
    // occur.
    const lineageSummary: CertificateLineageItem[] = (deletionRequest.janitor_wipes || [])
      .filter(wipe => wipe.status === 'SUCCEEDED')
      .map(wipe => ({
        system: wipe.destination,
        status: (wipe.details?.recordsFound === 0 || wipe.details?.rowsAffected === 0)
          ? ('CONFIRMED_ABSENT' as const)
          : ('ERASED' as const),
        timestamp: timestampToIso(wipe.updated_at),
      }));

    const keyDestructionStatus = (keyStatus.status === 'SHREDDED' || keyStatus.status === 'DELETED') ? 'COMPLETE' : 'PENDING';

    // See assertCascadeComplete: reachable only once every attempted
    // destination in janitor_wipes succeeded, so checked === succeeded here
    // in practice -- both are stated so the claim is self-contained.
    const destinationsChecked = deletionRequest.janitor_wipes?.length ?? 0;
    const destinationsSucceeded = (deletionRequest.janitor_wipes || []).filter(w => w.status === 'SUCCEEDED').length;

    return {
      iss: 'Chameleon Key Vault',
      sub: userId,
      tenantId,
      tenant_id: tenantId,
      user_id: userId,
      keyDestructionStatus,
      keyDestructionMethod: 'DEK_ERASURE',
      warehouseData: 'CRYPTOGRAPHICALLY UNREADABLE',
      iat: Math.floor(Date.now() / 1000),
      jti: `cert_${userId}_${Date.now()}`,
      shredDate: keyStatus.shredAt ?? new Date().toISOString(),
      shred_date: keyStatus.shredAt ?? new Date().toISOString(),
      keyFingerprint: await this.getKeyFingerprint(),
      lineageSummary,
      lineageCoverage: {
        destinationsChecked,
        destinationsSucceeded,
        knownDestinationTypes,
      },
      ghostDataSummary,
      ghost_data_summary: ghostDataSummary,
      ghostDataScanCoverage: 'NOT_TRACKED',
    };
  }

  async signClaims(claims: DestructionCertificateClaims): Promise<{ certificate: string; certificateHash: string }> {
    const keyVersionPath = await this.getCurrentSigningKeyVersion();

    const header = Buffer.from(JSON.stringify({
      alg: 'PS256',
      typ: 'JWT',
      kid: keyVersionPath,
    })).toString('base64url');
    const payload = Buffer.from(JSON.stringify(claims)).toString('base64url');
    const unsignedToken = `${header}.${payload}`;

    const signature = await this.signingKmsClient.asymmetricSign(unsignedToken, keyVersionPath);
    const certificate = `${unsignedToken}.${signature}`;
    const certificateHash = crypto.createHash('sha256').update(certificate).digest('hex');

    return { certificate, certificateHash };
  }

  private getSigningKeyBasePath(): string {
    return this.signingKmsClient.getCryptoKeyPath();
  }

  // Same caching shape as CertificateService's own copy -- deliberately not
  // shared between the two: this class uses its own CloudKMSClient instance
  // (see chameleon-paper/TEE_ATTESTATION_PLAN.md's "where the module lives"
  // section), so the two caches naturally stay independent, which is exactly
  // right for Phase 2, where they'll be genuinely separate deployed things.
  private _currentVersionCache: { value: string; expiresAt: number } | null = null;
  private readonly CURRENT_VERSION_TTL_MS = 5 * 60 * 1000;

  private async getCurrentSigningKeyVersion(): Promise<string> {
    const cached = this._currentVersionCache;
    if (cached && cached.expiresAt > Date.now()) return cached.value;
    const value = await this.signingKmsClient.getNewestEnabledVersion(this.getSigningKeyBasePath());
    this._currentVersionCache = { value, expiresAt: Date.now() + this.CURRENT_VERSION_TTL_MS };
    return value;
  }

  // Called by CertificateService.rotateSigningKey() after a real rotation.
  // This class uses its own separate CloudKMSClient instance (and so its
  // own separate cache) from CertificateService's -- without this, a
  // rotation would invalidate only the orchestrator's copy, and newly
  // issued certificates would keep silently signing with the old key
  // version for up to CURRENT_VERSION_TTL_MS, breaking the original,
  // pre-extraction code's explicit guarantee that rotation "takes effect
  // right away rather than waiting out the TTL." Found via a real failing
  // integration test during Phase 0's extraction, not by inspection.
  invalidateSigningKeyCache(): void {
    this._currentVersionCache = null;
  }

  private _fingerprintCache = new Map<string, string>();

  private async getKeyFingerprint(): Promise<string> {
    const keyVersionPath = await this.getCurrentSigningKeyVersion();
    const cached = this._fingerprintCache.get(keyVersionPath);
    if (cached) return cached;
    const pem = await this.signingKmsClient.getPublicKey(keyVersionPath);
    const keyObject = crypto.createPublicKey(pem);
    const der = keyObject.export({ type: 'spki', format: 'der' });
    const fingerprint = `sha256:${crypto.createHash('sha256').update(der).digest('hex')}`;
    this._fingerprintCache.set(keyVersionPath, fingerprint);
    return fingerprint;
  }
}
