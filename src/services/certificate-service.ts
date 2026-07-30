import * as crypto from 'crypto';
import { FirestoreRegistry } from '../gcp/firestore-registry.js';
import { BigQueryLineageRepository } from '../gcp/bigquery-lineage.js';
import { CloudKMSClient } from '../gcp/cloud-kms.js';
import { DeletionRequestRepository } from '../gcp/deletion-request-repository.js';
import { CertificateLineageItem, DestructionCertificateClaims } from '../types/index.js';
import { createLogger } from '../logging/index.js';
import { getRequiredEnv } from '../config/env.js';
import { GCSClient } from '../gcp/gcs-client.js';

const logger = createLogger('certificate-service');

export class CertificateService {
  constructor(
    private readonly firestoreRegistry: FirestoreRegistry,
    private readonly lineageRepo: BigQueryLineageRepository,
    private readonly signingKmsClient: CloudKMSClient,
    private readonly gcsClient: GCSClient,
    private readonly deletionRequestRepo: DeletionRequestRepository
  ) {}

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
  ): Promise<DestructionCertificateClaims> {
    logger.info({ userId, tenantId, deletionRequestId }, 'Generating destruction certificate claims');

    const keyStatus = await this.firestoreRegistry.getKeyStatus(userId, tenantId);

    if (!keyStatus || (keyStatus.status !== 'SHREDDED' && keyStatus.status !== 'DELETED')) {
      throw new Error(`Cannot generate certificate: Key for user ${userId} is not shredded.`);
    }

    const deletionRequest = deletionRequestId
      ? await this.deletionRequestRepo.getDeletionRequest(deletionRequestId)
      : await this.deletionRequestRepo.getLatestCompletedDeletionRequestForUser(userId, tenantId);

    if (!deletionRequest || (deletionRequest.status !== 'CASCADE_COMPLETE' && deletionRequest.status !== 'CERTIFICATE_ISSUED')) {
      throw new Error(`Cannot generate certificate: no completed deletion cascade found for user ${userId}`);
    }

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

    const claims: DestructionCertificateClaims = {
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
   * Issues, signs, and persists a Certificate of Destruction to GCS.
   */
  async issueAndStoreCertificate(userId: string, deletionRequestId: string, tenantId: string = 'default-tenant'): Promise<{ certificate: string; gcsPath: string }> {
    const claims = await this.generateCertificateClaims(userId, tenantId, deletionRequestId);
    const certificate = await this.signCertificate(claims);
    
    const auditHash = crypto.createHash('sha256').update(certificate).digest('hex');
    const gcsPath = await this.gcsClient.uploadCertificate(userId, deletionRequestId, certificate, auditHash, tenantId);
    
    return { certificate, gcsPath };
  }

  private getSigningKeyPath(): string {
    const projectId = getRequiredEnv('GCP_PROJECT_ID');
    const kmsRegion = getRequiredEnv('CLOUD_KMS_REGION');
    const kmsKeyRing = getRequiredEnv('CLOUD_KMS_SIGNING_KEY_RING');
    const kmsKeyName = getRequiredEnv('CLOUD_KMS_SIGNING_KEY_NAME');
    const kmsKeyVersion = process.env.CLOUD_KMS_SIGNING_KEY_VERSION || '1';
    return `projects/${projectId}/locations/${kmsRegion}/keyRings/${kmsKeyRing}/cryptoKeys/${kmsKeyName}/cryptoKeyVersions/${kmsKeyVersion}`;
  }

  async signCertificate(claims: DestructionCertificateClaims): Promise<string> {
    const keyVersionPath = this.getSigningKeyPath();

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
    return this.signingKmsClient.getPublicKey(this.getSigningKeyPath());
  }

  private _fingerprintCache: string | null = null;

  async getKeyFingerprint(): Promise<string> {
    if (this._fingerprintCache) return this._fingerprintCache;
    const pem = await this.getPublicKey();
    const keyObject = crypto.createPublicKey(pem);
    const der = keyObject.export({ type: 'spki', format: 'der' });
    const fingerprint = `sha256:${crypto.createHash('sha256').update(der).digest('hex')}`;
    this._fingerprintCache = fingerprint;
    return fingerprint;
  }

  async getJwks(): Promise<{ keys: Record<string, unknown>[] }> {
    const pem = await this.getPublicKey();
    const keyVersionPath = this.getSigningKeyPath();
    
    // Convert PEM to JWK format
    const keyObject = crypto.createPublicKey(pem);
    const jwk = keyObject.export({ format: 'jwk' });

    return {
      keys: [{
        ...jwk,
        kid: keyVersionPath,
        use: 'sig',
        alg: 'PS256'
      }]
    };
  }
}
