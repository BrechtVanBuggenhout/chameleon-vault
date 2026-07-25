import { KeyManagementServiceClient } from '@google-cloud/kms';
import * as crypto from 'crypto';
import { createLogger } from '../logging/index.js';
import { DeterministicAES } from '../crypto/deterministic-aes.js'; // Import DeterministicAES

const logger = createLogger('cloud-kms');

export class CloudKMSClient {
  private client: KeyManagementServiceClient;
  private projectId: string;
  private region: string;
  private keyRing: string;
  private keyName: string;

  constructor(
    projectId: string,
    region: string,
    keyRing: string,
    keyName: string
  ) {
    this.client = new KeyManagementServiceClient();
    this.projectId = projectId;
    this.region = region;
    this.keyRing = keyRing;
    this.keyName = keyName;
  }

  private getKeyPath(tenantId?: string): string {
    if (tenantId && tenantId !== 'default-tenant') {
      return this.client.cryptoKeyPath(
        this.projectId,
        this.region,
        this.keyRing,
        tenantId
      );
    }
    return this.client.cryptoKeyPath(
      this.projectId,
      this.region,
      this.keyRing,
      this.keyName
    );
  }

  /**
   * Ensures a tenant-specific CryptoKey exists. Creates it if it doesn't.
   */
  async ensureTenantKey(tenantId: string): Promise<string> {
    const keyPath = this.getKeyPath(tenantId);
    try {
      await this.client.getCryptoKey({ name: keyPath });
      return keyPath;
    } catch (error: any) {
      if (error.code === 5) { // NOT_FOUND
        logger.info({ tenantId }, 'Creating new dynamic KMS key for tenant');
        const parent = this.client.keyRingPath(this.projectId, this.region, this.keyRing);
        await this.client.createCryptoKey({
          parent,
          cryptoKeyId: tenantId,
          cryptoKey: {
            purpose: 'ENCRYPT_DECRYPT',
            nextRotationTime: { seconds: Math.floor(Date.now() / 1000) + 7776000 } // 90 days
          },
        });
        return keyPath;
      }
      throw error;
    }
  }

  async encryptDataEncryptionKey(dek: Buffer, tenantId?: string): Promise<Buffer> {
    try {
      const [encryptResponse] = await this.client.encrypt({
        name: this.getKeyPath(tenantId),
        plaintext: dek,
      });

      if (!encryptResponse.ciphertext) {
        throw new Error('Cloud KMS encryption failed: no ciphertext returned');
      }

      logger.debug('Successfully encrypted DEK with Cloud KMS');
      return Buffer.from(encryptResponse.ciphertext);
    } catch (error) {
      logger.error({ error }, 'Failed to encrypt DEK with Cloud KMS');
      throw error;
    }
  }

  async decryptDataEncryptionKey(encryptedDek: Buffer, tenantId?: string): Promise<Buffer> {
    try {
      const [decryptResponse] = await this.client.decrypt({
        name: this.getKeyPath(tenantId),
        ciphertext: encryptedDek,
      });

      if (!decryptResponse.plaintext) {
        throw new Error('Cloud KMS decryption failed: no plaintext returned');
      }

      logger.debug('Successfully decrypted DEK with Cloud KMS');
      return Buffer.from(decryptResponse.plaintext);
    } catch (error) {
      logger.error({ error }, 'Failed to decrypt DEK with Cloud KMS');
      throw error;
    }
  }

  async generateAndEncryptDek(tenantId?: string): Promise<Buffer> {
    try {
      const newDek = DeterministicAES.generateRandomDEK();
      return this.encryptDataEncryptionKey(newDek, tenantId);
    } catch (error) {
      logger.error({ error }, 'Failed to generate and encrypt new DEK with Cloud KMS');
      throw new Error('Failed to generate and encrypt new DEK');
    }
  }

  /**
   * Signs a payload using an asymmetric key for Phase 4 compliance proofs.
   */
  async asymmetricSign(payload: string, keyVersionPath: string): Promise<string> {
    try {
      const digest = crypto.createHash('sha256').update(payload).digest();
      
      const [signResponse] = await this.client.asymmetricSign({
        name: keyVersionPath,
        digest: { sha256: digest },
      });

      if (!signResponse.signature) {
        throw new Error('Cloud KMS asymmetric signing failed');
      }

      return Buffer.from(signResponse.signature).toString('base64url');
    } catch (error) {
      logger.error({ error, keyVersionPath }, 'Asymmetric signing failed');
      throw error;
    }
  }

  async getPublicKey(keyVersionPath: string): Promise<string> {
    try {
      const [publicKey] = await this.client.getPublicKey({
        name: keyVersionPath,
      });
      return publicKey.pem || '';
    } catch (error) {
      logger.error({ error, keyVersionPath }, 'Failed to fetch public key');
      throw error;
    }
  }
}
