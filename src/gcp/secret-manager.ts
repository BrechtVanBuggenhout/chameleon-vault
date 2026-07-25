import { SecretManagerServiceClient } from '@google-cloud/secret-manager';
import { createLogger } from '../logging/index.js';

const logger = createLogger('secret-manager');

export interface CMEKMetadata {
  regionalKeyRingName: string;
  bigqueryKeyRingName: string;
  bigqueryKeyName: string;
  firestoreKeyName: string;
  gcsKeyName: string;
  rotationPeriod: string;
  environment: string;
}

export class SecretManagerClient {
  private client: SecretManagerServiceClient;
  private projectId: string;
  private secretName: string;

  constructor(projectId: string, secretName: string) {
    this.client = new SecretManagerServiceClient();
    this.projectId = projectId;
    this.secretName = secretName;
  }

  private getSecretPath(): string {
    return this.client.secretPath(this.projectId, this.secretName);
  }

  async getCMEKMetadata(): Promise<CMEKMetadata> {
    try {
      const [version] = await this.client.accessSecretVersion({
        name: `${this.getSecretPath()}/versions/latest`,
      });

      if (!version.payload?.data) {
        throw new Error('Secret Manager returned empty payload');
      }

      const secretValue =
        typeof version.payload?.data === 'string'
          ? version.payload.data
          : Buffer.from(version.payload?.data || '').toString('utf8');

      const metadata = JSON.parse(secretValue) as CMEKMetadata;
      logger.debug('Successfully retrieved CMEK metadata from Secret Manager');
      return metadata;
    } catch (error) {
      logger.error({ error }, 'Failed to retrieve CMEK metadata');
      throw error;
    }
  }

  async updateCMEKMetadata(metadata: CMEKMetadata): Promise<void> {
    try {
      await this.client.addSecretVersion({
        parent: this.getSecretPath(),
        payload: {
          data: Buffer.from(JSON.stringify(metadata)),
        },
      });

      logger.info('Successfully updated CMEK metadata in Secret Manager');
    } catch (error) {
      logger.error({ error }, 'Failed to update CMEK metadata');
      throw error;
    }
  }
}
