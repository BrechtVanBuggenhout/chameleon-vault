import * as crypto from 'crypto';
import { FirestoreRegistry } from '../gcp/firestore-registry.js';
import { BigQueryLineageRepository } from '../gcp/bigquery-lineage.js';
import { CloudKMSClient } from '../gcp/cloud-kms.js';
import { DeletionRequestRepository } from '../gcp/deletion-request-repository.js';
import { CertificateChainRepository } from '../gcp/certificate-chain-repository.js';
import { CertificateLineageItem, DestructionCertificateClaims, KeyStatus } from '../types/index.js';
import { DeletionRequest } from '../types/deletion-request.js';
import { createLogger } from '../logging/index.js';
import { GCSClient } from '../gcp/gcs-client.js';

const logger = createLogger('certificate-service');

export class CertificateService {
  constructor(
    private readonly firestoreRegistry: FirestoreRegistry,
    private readonly lineageRepo: BigQueryLineageRepository,
    private readonly signingKmsClient: CloudKMSClient,
    private readonly gcsClient: GCSClient,
    private readonly deletionRequestRepo: DeletionRequestRepository,
    private readonly chainRepository: CertificateChainRepository
  ) {}

  // Shared by generateCertificateClaims and getCertificateForUser so both
  // enforce the exact same eligibility rule (and error wording) for issuing
  // or returning a certificate -- key must be shredded, and a real deletion
  // cascade must have actually completed. Split into two assertion
  // functions (rather than one checking both) because a TS `asserts x is Y`
  // clause can only narrow a single identifier.
  private assertKeyShredded(userId: string, keyStatus: KeyStatus | null): asserts keyStatus is KeyStatus {
    if (!keyStatus || (keyStatus.status !== 'SHREDDED' && keyStatus.status !== 'DELETED')) {
      throw new Error(`Cannot generate certificate: Key for user ${userId} is not shredded.`);
    }
  }

  private assertCascadeComplete(userId: string, deletionRequest: DeletionRequest | null): asserts deletionRequest is DeletionRequest {
    if (!deletionRequest || (deletionRequest.status !== 'CASCADE_COMPLETE' && deletionRequest.status !== 'CERTIFICATE_ISSUED')) {
      throw new Error(`Cannot generate certificate: no completed deletion cascade found for user ${userId}`);
    }
  }

  /**
   * Generates the unsigned claims for a Certificate of Destruction.
   *
   * Gated on a real, completed deletion cascade -- not just the key being
   * shredded. Previously this pulled destination names from raw lineage
   * events/Firestore hot-path data and stamped every one of them 'ERASED'
   * unconditionally, with no check that a cascade wipe had ever actually
   * run or succeeded for this user. That let GET /certificate/:userId issue
   * a signed certificate claiming destinations were erased when nothing
   * had been verified. lineageSummary now comes only from the deletion
   * request's own janitor_wipes -- the same real, per-destination
   * SUCCEEDED/FAILED results the CASCADE_COMPLETE gate already relies on --
   * so a certificate can only ever repeat what was actually confirmed.
   */
  async generateCertificateClaims(
    userId: string,
    tenantId: string = 'default-tenant',
    deletionRequestId?: string
  ): Promise<Omit<DestructionCertificateClaims, 'previousCertificateHash' | 'chainSequence'>> {
    logger.info({ userId, tenantId, deletionRequestId }, 'Generating destruction certificate claims');

    const keyStatus = await this.firestoreRegistry.getKeyStatus(userId, tenantId);

    const deletionRequest = deletionRequestId
      ? await this.deletionRequestRepo.getDeletionRequest(deletionRequestId)
      : await this.deletionRequestRepo.getLatestCompletedDeletionRequestForUser(userId, tenantId);

    this.assertKeyShredded(userId, keyStatus);
    this.assertCascadeComplete(userId, deletionRequest);

    // Only ever built from real, recorded outcomes -- never re-derived from
    // raw lineage/destination-name data. Filtering to SUCCEEDED is
    // defensive, not load-bearing: CASCADE_COMPLETE is only reachable when
    // every wipe succeeded (see deletion-request-service.ts), so a FAILED
    // entry here should never actually occur.
    const lineageSummary: CertificateLineageItem[] = (deletionRequest.janitor_wipes || [])
      .filter(wipe => wipe.status === 'SUCCEEDED')
      .map(wipe => ({
        system: wipe.destination,
        status: wipe.details?.recordsFound === 0 ? ('CONFIRMED_ABSENT' as const) : ('ERASED' as const),
        timestamp: wipe.updated_at instanceof Date ? wipe.updated_at.toISOString() : String(wipe.updated_at),
      }));

    const ghostDataSummary = await this.lineageRepo.getGhostDataFindings(userId, tenantId);

    const keyDestructionStatus = (keyStatus.status === 'SHREDDED' || keyStatus.status === 'DELETED') ? 'COMPLETE' : 'PENDING';

    const claims: Omit<DestructionCertificateClaims, 'previousCertificateHash' | 'chainSequence'> = {
      iss: 'Chameleon Key Vault',
      sub: userId,
      tenantId,
      tenant_id: tenantId,
      user_id: userId, // Add snake_case alias for auditors
      keyDestructionStatus,
      warehouseData: 'CRYPTOGRAPHICALLY UNREADABLE',
      iat: Math.floor(Date.now() / 1000),
      jti: `cert_${userId}_${Date.now()}`,
      shredDate: keyStatus.shredAt ?? new Date().toISOString(),
      shred_date: keyStatus.shredAt ?? new Date().toISOString(), // Add snake_case alias for auditors
      keyFingerprint: await this.getKeyFingerprint(),
      lineageSummary,
      ghostDataSummary,
      ghost_data_summary: ghostDataSummary,
    };

    return claims;
  }

  /**
   * Issues, signs, and persists a Certificate of Destruction to GCS. This is
   * the one place a certificate is ever actually added to the tenant's hash
   * chain -- see CertificateChainRepository.appendToChain for why the sign
   * happens inside that transaction (reserves the sequence/previous-hash
   * atomically, so two deletions completing for the same tenant at once
   * can't corrupt the chain).
   */
  async issueAndStoreCertificate(userId: string, deletionRequestId: string, tenantId: string = 'default-tenant'): Promise<{ certificate: string; gcsPath: string }> {
    const baseClaims = await this.generateCertificateClaims(userId, tenantId, deletionRequestId);

    const { certificate, certificateHash, previousHash, sequence } = await this.chainRepository.appendToChain(
      tenantId,
      deletionRequestId,
      async (previousCertificateHash, chainSequence) => {
        const claims: DestructionCertificateClaims = { ...baseClaims, previousCertificateHash, chainSequence };
        const signed = await this.signCertificate(claims);
        const hash = crypto.createHash('sha256').update(signed).digest('hex');
        return { certificate: signed, certificateHash: hash };
      }
    );

    const gcsPath = await this.gcsClient.uploadCertificate(
      userId,
      deletionRequestId,
      certificate,
      certificateHash,
      tenantId,
      { previousCertificateHash: previousHash, chainSequence: sequence }
    );

    return { certificate, gcsPath };
  }

  /**
   * Returns the Certificate of Destruction for a user, preferring the
   * exact certificate that was actually issued and chained (read back from
   * GCS via the deletion request's stored certificate_gcs_path) over
   * re-signing a fresh one -- signing produces a different jti/iat/
   * signature every time, so calling this repeatedly used to hand back a
   * different "valid" certificate for the same deletion on every request.
   *
   * Falls back to re-signing on demand (unchained, not persisted) only for
   * a request stuck at CASCADE_COMPLETE with no certificate ever actually
   * stored -- e.g. a prior CERTIFICATE_ISSUED transition that failed after
   * the status write but before/during GCS upload. A GET must never
   * silently mutate deletion-request state or consume a slot in the
   * tenant's certificate chain, so this fallback does neither.
   */
  async getCertificateForUser(userId: string, tenantId: string = 'default-tenant'): Promise<{ certificate: string; stored: boolean }> {
    const [keyStatus, deletionRequest] = await Promise.all([
      this.firestoreRegistry.getKeyStatus(userId, tenantId),
      this.deletionRequestRepo.getLatestCompletedDeletionRequestForUser(userId, tenantId),
    ]);
    this.assertKeyShredded(userId, keyStatus);
    this.assertCascadeComplete(userId, deletionRequest);

    if (deletionRequest.status === 'CERTIFICATE_ISSUED' && deletionRequest.certificate_gcs_path) {
      const stored = await this.gcsClient.downloadCertificate(deletionRequest.certificate_gcs_path);
      return { certificate: stored.certificate, stored: true };
    }

    const claims = await this.generateCertificateClaims(userId, tenantId, deletionRequest.deletion_request_id);
    const certificate = await this.signCertificate({ ...claims, previousCertificateHash: null, chainSequence: null });
    return { certificate, stored: false };
  }

  // Base (unversioned) path of the signing CryptoKey -- static for the
  // process lifetime, unlike the current *version*, which changes on rotation.
  private getSigningKeyBasePath(): string {
    return this.signingKmsClient.getCryptoKeyPath();
  }

  // "Current" (the newest ENABLED version -- see getNewestEnabledVersion's
  // own comment for why that's the right definition) changes only when
  // rotateSigningKey() runs, so this is cached briefly rather than
  // refetched from KMS on every sign/JWKS call. Invalidated immediately on
  // rotation so it takes effect right away rather than waiting out the TTL.
  private _currentVersionCache: { value: string; expiresAt: number } | null = null;
  private readonly CURRENT_VERSION_TTL_MS = 5 * 60 * 1000;

  private async getCurrentSigningKeyVersion(): Promise<string> {
    const cached = this._currentVersionCache;
    if (cached && cached.expiresAt > Date.now()) return cached.value;
    const value = await this.signingKmsClient.getNewestEnabledVersion(this.getSigningKeyBasePath());
    this._currentVersionCache = { value, expiresAt: Date.now() + this.CURRENT_VERSION_TTL_MS };
    return value;
  }

  async signCertificate(claims: DestructionCertificateClaims): Promise<string> {
    const keyVersionPath = await this.getCurrentSigningKeyVersion();

    const header = Buffer.from(JSON.stringify({
      alg: 'PS256',
      typ: 'JWT',
      kid: keyVersionPath // Use full KMS resource name as kid for rotation mapping
    })).toString('base64url');

    const payload = Buffer.from(JSON.stringify(claims)).toString('base64url');

    const unsignedToken = `${header}.${payload}`;

    const signature = await this.signingKmsClient.asymmetricSign(unsignedToken, keyVersionPath);

    return `${unsignedToken}.${signature}`;
  }

  async getPublicKey(): Promise<string> {
    const keyVersionPath = await this.getCurrentSigningKeyVersion();
    return this.signingKmsClient.getPublicKey(keyVersionPath);
  }

  // Keyed by version path -- a given version's public key/fingerprint never
  // changes once ENABLED, so unlike the primary-version cache above this
  // never needs a TTL or invalidation, just one entry per version ever seen.
  private _fingerprintCache = new Map<string, string>();

  async getKeyFingerprint(): Promise<string> {
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

  // Same never-expires reasoning as _fingerprintCache: a version's JWK is
  // immutable once ENABLED.
  private _jwkCache = new Map<string, Record<string, unknown>>();
  private _enabledVersionsCache: { value: string[]; expiresAt: number } | null = null;
  private readonly ENABLED_VERSIONS_TTL_MS = 10 * 60 * 1000;

  private async getEnabledVersions(): Promise<string[]> {
    const cached = this._enabledVersionsCache;
    if (cached && cached.expiresAt > Date.now()) return cached.value;
    const value = await this.signingKmsClient.listEnabledVersions(this.getSigningKeyBasePath());
    this._enabledVersionsCache = { value, expiresAt: Date.now() + this.ENABLED_VERSIONS_TTL_MS };
    return value;
  }

  /**
   * Every ENABLED signing key version, past and present -- not just the
   * current primary. Old certificates carry a `kid` pointing at whichever
   * version signed them, so a verifier resolving that `kid` against this set
   * needs every version still around, not only the one currently signing new
   * certificates. Old versions are kept indefinitely (never destroyed) so a
   * certificate issued years ago stays verifiable.
   */
  async getJwks(): Promise<{ keys: Record<string, unknown>[] }> {
    const versions = await this.getEnabledVersions();

    const keys = await Promise.all(versions.map(async (keyVersionPath) => {
      const cached = this._jwkCache.get(keyVersionPath);
      if (cached) return cached;
      const pem = await this.signingKmsClient.getPublicKey(keyVersionPath);
      const keyObject = crypto.createPublicKey(pem);
      const jwk = {
        ...keyObject.export({ format: 'jwk' }),
        kid: keyVersionPath,
        use: 'sig',
        alg: 'PS256',
      };
      this._jwkCache.set(keyVersionPath, jwk);
      return jwk;
    }));

    return { keys };
  }

  /**
   * Mints a new signing key version. It becomes "current" the moment it
   * exists (see getNewestEnabledVersion) -- no separate promotion step, KMS
   * doesn't support one for ASYMMETRIC_SIGN keys. The old version is left
   * ENABLED (never destroyed), so certificates it already signed remain
   * verifiable via getJwks() indefinitely.
   */
  async rotateSigningKey(): Promise<{ newVersion: string; previousVersion: string }> {
    const basePath = this.getSigningKeyBasePath();
    const previousVersion = await this.getCurrentSigningKeyVersion();

    const newVersion = await this.signingKmsClient.createKeyVersion(basePath);
    await this.signingKmsClient.waitForVersionEnabled(newVersion);

    // Invalidate so the new version takes effect immediately rather than
    // waiting out the caches' TTLs.
    this._currentVersionCache = null;
    this._enabledVersionsCache = null;

    logger.info({ previousVersion, newVersion }, 'Signing key rotated');
    return { newVersion, previousVersion };
  }
}
