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

  /** The base CryptoKey path (no version) this client was constructed for. */
  getCryptoKeyPath(): string {
    return this.getKeyPath();
  }

  /** Full resource name of the key's current primary (signing) version. */
  async getPrimaryVersion(keyPath: string): Promise<string> {
    const [cryptoKey] = await this.client.getCryptoKey({ name: keyPath });
    const primary = cryptoKey.primary?.name;
    if (!primary) {
      throw new Error(`CryptoKey ${keyPath} has no primary version`);
    }
    return primary;
  }

  /**
   * Every non-destroyed, usable version of the key -- old versions are kept
   * (never destroyed) so certificates signed under them stay verifiable, so
   * this can return an unbounded, ever-growing list over the key's lifetime.
   */
  async listEnabledVersions(keyPath: string): Promise<string[]> {
    const versions: string[] = [];
    for await (const version of this.client.listCryptoKeyVersionsAsync({ parent: keyPath })) {
      if (version.state === 'ENABLED' && version.name) {
        versions.push(version.name);
      }
    }
    return versions;
  }

  /** Mints a new key version. Callers must wait for it to become ENABLED before signing with it. */
  async createKeyVersion(keyPath: string): Promise<string> {
    const [version] = await this.client.createCryptoKeyVersion({
      parent: keyPath,
      cryptoKeyVersion: {},
    });
    if (!version.name) {
      throw new Error(`Failed to create a new version for ${keyPath}`);
    }
    return version.name;
  }

  /**
   * Asymmetric key versions generate their key material asynchronously --
   * polls until the new version is actually usable (or fails/times out).
   */
  async waitForVersionEnabled(versionName: string, timeoutMs = 120_000, pollMs = 3_000): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const [version] = await this.client.getCryptoKeyVersion({ name: versionName });
      if (version.state === 'ENABLED') return;
      if (version.state === 'GENERATION_FAILED') {
        throw new Error(`Key version ${versionName} failed to generate`);
      }
      if (Date.now() >= deadline) {
        throw new Error(`Timed out waiting for key version ${versionName} to become ENABLED (last state: ${version.state})`);
      }
      await new Promise(resolve => setTimeout(resolve, pollMs));
    }
  }

  /** Promotes a version to be the key's primary -- new signatures use it from this point on. */
  async promoteVersion(keyPath: string, versionName: string): Promise<void> {
    const cryptoKeyVersionId = versionName.split('/').pop();
    if (!cryptoKeyVersionId) {
      throw new Error(`Could not extract version id from ${versionName}`);
    }
    await this.client.updateCryptoKeyPrimaryVersion({
      name: keyPath,
      cryptoKeyVersionId,
    });
  }
}
