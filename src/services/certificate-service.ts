import * as crypto from 'crypto';
import { FirestoreRegistry } from '../gcp/firestore-registry.js';
import { BigQueryLineageRepository } from '../gcp/bigquery-lineage.js';
import { CloudKMSClient } from '../gcp/cloud-kms.js';
import { DeletionRequestRepository } from '../gcp/deletion-request-repository.js';
import { CertificateChainRepository } from '../gcp/certificate-chain-repository.js';
import { DestructionCertificateClaims, KeyStatus } from '../types/index.js';
import { DeletionRequest } from '../types/deletion-request.js';
import { createLogger } from '../logging/index.js';
import { CHAIN_ANCHOR_MARKER } from '../logging/audit-anchor.js';
import { GCSClient } from '../gcp/gcs-client.js';
import { TsaClient, TsaTimestampInfo } from '../gcp/tsa-client.js';
import { RekorClient, RekorLogEntryInfo } from '../gcp/rekor-client.js';
import { connectorRegistry } from './registry.js';
import { CertificateSigner } from '../certificate-signer/sign.js';

const logger = createLogger('certificate-service');

export class CertificateService {
  constructor(
    private readonly firestoreRegistry: FirestoreRegistry,
    private readonly lineageRepo: BigQueryLineageRepository,
    private readonly signingKmsClient: CloudKMSClient,
    private readonly gcsClient: GCSClient,
    private readonly deletionRequestRepo: DeletionRequestRepository,
    private readonly chainRepository: CertificateChainRepository,
    private readonly certificateSigner: CertificateSigner,
    private readonly tsaClient?: TsaClient,
    private readonly rekorClient?: RekorClient
  ) {}

  // Used by getCertificateForUser below for its own early-exit branching
  // (stored vs. regenerate) -- a separate, smaller copy of the same
  // assertions CertificateSigner.generateClaims makes independently inside
  // the trust boundary (see certificate-signer/sign.ts). Harmless
  // duplication, not a security concession: this copy exists for control
  // flow here, not as something the signer trusts instead of checking
  // itself. Split into two assertion functions (rather than one checking
  // both) because a TS `asserts x is Y` clause can only narrow a single
  // identifier.
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
   * Issues, signs, and persists a Certificate of Destruction to GCS. This is
   * the one place a certificate is ever actually added to the tenant's hash
   * chain -- see CertificateChainRepository.appendToChain for why the sign
   * happens inside that transaction (reserves the sequence/previous-hash
   * atomically, so two deletions completing for the same tenant at once
   * can't corrupt the chain).
   *
   * The actual issuance decision (is the key really shredded, did the
   * cascade really complete, what should the claims say) lives in
   * CertificateSigner now, not here -- see
   * chameleon-paper/TEE_ATTESTATION_PLAN.md. This method is the orchestrator:
   * it fetches the two caller-supplied-but-non-authoritative inputs
   * (ghostDataSummary, knownDestinationTypes -- see CertificateSigner's own
   * doc comment for why those two specifically are safe to pre-fetch here
   * rather than re-derived inside the trust boundary), owns the chain
   * transaction, and handles everything that happens after a certificate is
   * signed (TSA, Rekor, GCS).
   */
  async issueAndStoreCertificate(userId: string, deletionRequestId: string, tenantId: string = 'default-tenant'): Promise<{ certificate: string; gcsPath: string }> {
    const ghostDataSummary = await this.lineageRepo.getGhostDataFindings(userId, tenantId);
    const baseClaims = await this.certificateSigner.generateClaims({
      userId,
      tenantId,
      deletionRequestId,
      ghostDataSummary,
      knownDestinationTypes: connectorRegistry.getRegisteredConnectorNames(),
    });

    const { certificate, certificateHash, previousHash, sequence } = await this.chainRepository.appendToChain(
      tenantId,
      deletionRequestId,
      async (previousCertificateHash, chainSequence) => {
        const claims: DestructionCertificateClaims = { ...baseClaims, previousCertificateHash, chainSequence };
        return this.certificateSigner.signClaims(claims);
      }
    );

    // Timestamps the final signed JWT, never inside the transaction closure
    // above -- appendToChain's own docs say `sign` may run more than once
    // under Firestore contention, and multiplying calls to a free, no-SLA
    // TSA on retries is a real risk worth avoiding. Reuses certificateHash
    // (already computed once above) as the TSA message imprint -- never
    // rehashed. Must be awaited, not fire-and-forget: this service runs
    // min_instance_count=0, and the rotate-endpoint bug fixed earlier this
    // session confirmed Cloud Run can reap an instance the moment a
    // response is sent regardless of cpu_idle. TsaClient.requestTimestamp
    // never throws, so this can only add latency, never a new failure mode.
    let tsaTimestamp: TsaTimestampInfo | undefined;
    if (this.tsaClient) {
      tsaTimestamp = await this.tsaClient.requestTimestamp(certificateHash);
      logger.info(
        {
          [CHAIN_ANCHOR_MARKER]: true,
          auditEventType: tsaTimestamp.status === 'OBTAINED' ? 'tsa_timestamp_obtained' : 'tsa_timestamp_failed',
          certificateHash,
          tsaUrl: tsaTimestamp.tsaUrl,
        },
        'RFC 3161 timestamp attempted'
      );

      // Best-effort follow-up write against the already-committed chain
      // entry. A failure here must never surface as a failure of
      // issueAndStoreCertificate -- the certificate is already fully valid
      // and chained without it, and the GCS wrapper below (the real source
      // of truth for the public verification API) still gets the result
      // either way.
      try {
        await this.chainRepository.recordTsaTimestamp(certificateHash, tsaTimestamp);
      } catch (error) {
        logger.error({ error, certificateHash }, 'Failed to persist TSA timestamp to chain entry -- issuance unaffected');
      }
    }

    // Rekor transparency-log publishing: same must-await reasoning as TSA
    // above (min_instance_count=0, Cloud Run can reap the instance the
    // moment a response is sent). Publishes hashes only -- certificateHash
    // and previousHash, never tenantId/userId -- so the public log can't
    // become an enumerable record of who was deleted when. RekorClient never
    // throws, so this can only add latency, never a new failure mode.
    let rekorEntry: RekorLogEntryInfo | undefined;
    if (this.rekorClient) {
      rekorEntry = await this.rekorClient.publishCertificateHash(certificateHash, previousHash);
      logger.info(
        {
          [CHAIN_ANCHOR_MARKER]: true,
          auditEventType: rekorEntry.status === 'PUBLISHED' ? 'rekor_entry_published' : 'rekor_entry_failed',
          certificateHash,
          rekorUrl: rekorEntry.rekorUrl,
        },
        'Rekor transparency log entry attempted'
      );

      try {
        await this.chainRepository.recordRekorEntry(certificateHash, rekorEntry);
      } catch (error) {
        logger.error({ error, certificateHash }, 'Failed to persist Rekor entry to chain entry -- issuance unaffected');
      }
    }

    const gcsPath = await this.gcsClient.uploadCertificate(
      userId,
      deletionRequestId,
      certificate,
      certificateHash,
      tenantId,
      { previousCertificateHash: previousHash, chainSequence: sequence },
      tsaTimestamp,
      rekorEntry
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

    const ghostDataSummary = await this.lineageRepo.getGhostDataFindings(userId, tenantId);
    const baseClaims = await this.certificateSigner.generateClaims({
      userId,
      tenantId,
      deletionRequestId: deletionRequest.deletion_request_id,
      ghostDataSummary,
      knownDestinationTypes: connectorRegistry.getRegisteredConnectorNames(),
    });
    const { certificate } = await this.certificateSigner.signClaims({ ...baseClaims, previousCertificateHash: null, chainSequence: null });
    return { certificate, stored: false };
  }

  /**
   * Looks up a previously-issued certificate by its own hash -- the backing
   * lookup for chain-continuity verification (walking previousCertificateHash
   * backward through a tenant's chain, see scripts/verify-cert.ts). Public by
   * design: a hash is only known to someone who already holds a real chained
   * certificate (it's the previousCertificateHash inside it), so this can't
   * be used to enumerate a tenant's certificate history the way a
   * by-sequence lookup could.
   */
  async getCertificateByHash(certificateHash: string): Promise<{ certificate: string; tsaTimestamp?: TsaTimestampInfo } | null> {
    const entry = await this.chainRepository.getEntryByHash(certificateHash);
    if (!entry) return null;

    const deletionRequest = await this.deletionRequestRepo.getDeletionRequest(entry.deletion_request_id);
    if (!deletionRequest?.certificate_gcs_path) return null;

    // tsaTimestamp is read from the GCS wrapper (below), not the Firestore
    // entry above -- GCS is the source of truth a Firestore write failure
    // in issueAndStoreCertificate's best-effort follow-up can never affect.
    const stored = await this.gcsClient.downloadCertificate(deletionRequest.certificate_gcs_path);
    return { certificate: stored.certificate, tsaTimestamp: stored.tsaTimestamp };
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

  async getPublicKey(): Promise<string> {
    const keyVersionPath = await this.getCurrentSigningKeyVersion();
    return this.signingKmsClient.getPublicKey(keyVersionPath);
  }

  // Returns null when Rekor publishing isn't configured, rather than
  // throwing -- a deployment with REKOR_ENABLED unset simply has nothing to
  // return here, same as any other optional feature's absence.
  async getRekorPublicKey(): Promise<string | null> {
    if (!this.rekorClient) return null;
    return this.rekorClient.getPublicKeyPem();
  }

  // Same never-expires reasoning as the version cache above: a version's JWK is
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
    // waiting out the caches' TTLs -- including certificateSigner's own,
    // separate cache (it uses its own CloudKMSClient instance, so its cache
    // is never invalidated by the two lines above). Found missing via a
    // real failing integration test during Phase 0's extraction: without
    // this, a rotation would silently leave certificate issuance signing
    // with the old key version for up to five minutes.
    this._currentVersionCache = null;
    this._enabledVersionsCache = null;
    this.certificateSigner.invalidateSigningKeyCache();

    // Marked and worded identically to appendToChain's chain-anchor log line
    // (same CHAIN_ANCHOR_MARKER, matched by the same Cloud Logging sink
    // filter in chameleon-infra-gcp/audit_logging.tf) so rotation gets the
    // same tamper-evident, Bucket-Lock-protected export that certificate
    // issuance already gets -- previously this was a plain log line with no
    // export anywhere, which would have made KEY_ROTATION_POLICY.md's
    // claims about rotation being audited false.
    logger.info(
      { [CHAIN_ANCHOR_MARKER]: true, auditEventType: 'signing_key_rotated', previousVersion, newVersion },
      'Signing key rotated'
    );
    return { newVersion, previousVersion };
  }
}
