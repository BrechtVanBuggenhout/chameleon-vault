import { Storage } from '@google-cloud/storage';
import { createLogger } from '../logging/index.js';

const logger = createLogger('gcs-client');

export class GCSClient {
  private storage: Storage;
  private bucketName: string;

  constructor(projectId: string, bucketName: string) {
    this.storage = new Storage({ projectId });
    this.bucketName = bucketName;
  }

  /**
   * Uploads a Certificate of Destruction (JWT) to the audit evidence bucket.
   */
  async uploadCertificate(
    userId: string,
    deletionRequestId: string,
    certificate: string,
    hash: string,
    tenantId: string = 'default-tenant'
  ): Promise<string> {
    try {
      const now = new Date();
      const datePath = `${now.getFullYear()}/${String(now.getMonth() + 1).padStart(2, '0')}/${String(now.getDate()).padStart(2, '0')}`;
      const certPath = `certificates/${tenantId}/${datePath}/certificate-${deletionRequestId}.json`;
      const hashPath = `certificates/${tenantId}/${datePath}/audit-hash-${deletionRequestId}.txt`;
      
      const bucket = this.storage.bucket(this.bucketName);

      // Save certificate JSON wrapper as required by infra specs
      const certPayload = JSON.stringify({
        certificate,
        userId,
        deletionRequestId,
        timestamp: now.toISOString(),
        hash
      });

      await bucket.file(certPath).save(certPayload, {
        metadata: {
          contentType: 'application/json',
          metadata: {
            'audit-trail-hash': hash,
            'user-id': userId,
            'deletion-request-id': deletionRequestId,
            'tenant-id': tenantId
          }
        }
      });

      // Save hash to the dedicated metadata path (audit-hash.txt)
      // This provides the non-repudiable hash of the destruction event.
      await bucket.file(hashPath).save(hash, {
        metadata: {
          contentType: 'text/plain',
          metadata: { 'user-id': userId }
        }
      });

      logger.info({ userId, deletionRequestId, certPath }, 'Certificate and audit hash uploaded to GCS');
      return `gs://${this.bucketName}/${certPath}`;
    } catch (error) {
      logger.error({ error, userId }, 'Failed to upload certificate to GCS');
      throw error;
    }
  }
}