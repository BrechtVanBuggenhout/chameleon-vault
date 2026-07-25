import { createCipheriv, createDecipheriv, randomBytes, createHash } from 'crypto';
import { createLogger } from '../logging/index.js';

const logger = createLogger('deterministic-aes');

// AES-256-GCM uses 32-byte keys and 12-byte IVs
const KEY_SIZE = 32; // 256 bits
const IV_SIZE = 12; // 96 bits for GCM
const AUTH_TAG_SIZE = 16; // 128 bits for GCM
const ALGORITHM = 'aes-256-gcm';

export interface EncryptionResult {
  ciphertext: string; // Base64-encoded
  userId: string;
  timestamp: string;
}

export interface DecryptionResult {
  plaintext: string;
  userId: string;
  timestamp: string;
}

export class DeterministicAES {
  /**
   * Generate a deterministic IV from userId.
   * Same userId always produces the same IV (deterministic property).
   * IV is derived using SHA-256 hash truncated to 12 bytes.
   */
  static generateDeterministicIV(userId: string): Buffer {
    const hash = createHash('sha256').update(userId).digest();
    return hash.slice(0, IV_SIZE);
  }

  /**
   * Encrypt plaintext using deterministic AES-256-GCM.
   * Same plaintext + userId + key = same ciphertext (deterministic).
   */
  static encrypt(
    plaintext: string,
    userId: string,
    dek: Buffer
  ): EncryptionResult {
    try {
      if (dek.length !== KEY_SIZE) {
        throw new Error(`DEK must be ${KEY_SIZE} bytes, got ${dek.length}`);
      }

      const iv = this.generateDeterministicIV(userId);
      const aad = Buffer.from(userId); // Additional Authenticated Data

      const cipher = createCipheriv(ALGORITHM, dek, iv);
      cipher.setAAD(aad);

      let ciphertext = cipher.update(plaintext, 'utf8', 'hex');
      ciphertext += cipher.final('hex');

      const authTag = cipher.getAuthTag();
      const combined = Buffer.concat([
        Buffer.from(ciphertext, 'hex'),
        authTag,
      ]);

      logger.debug(
        { userId, plaintextLength: plaintext.length },
        'Successfully encrypted plaintext'
      );

      return {
        ciphertext: combined.toString('base64'),
        userId,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      logger.error(
        { error, userId },
        'Failed to encrypt plaintext'
      );
      throw error;
    }
  }

  /**
   * Decrypt ciphertext using AES-256-GCM.
   * Verifies GCM authentication tag; fails if tampered.
   */
  static decrypt(
    ciphertextB64: string,
    userId: string,
    dek: Buffer
  ): DecryptionResult {
    try {
      if (dek.length !== KEY_SIZE) {
        throw new Error(`DEK must be ${KEY_SIZE} bytes, got ${dek.length}`);
      }

      const combined = Buffer.from(ciphertextB64, 'base64');

      if (combined.length < AUTH_TAG_SIZE) {
        throw new Error('Invalid ciphertext: too short');
      }

      const ciphertext = combined.slice(0, combined.length - AUTH_TAG_SIZE);
      const authTag = combined.slice(combined.length - AUTH_TAG_SIZE);

      const iv = this.generateDeterministicIV(userId);
      const aad = Buffer.from(userId);

      const decipher = createDecipheriv(ALGORITHM, dek, iv);
      decipher.setAAD(aad);
      decipher.setAuthTag(authTag);

      let plaintext = decipher.update(ciphertext.toString('hex'), 'hex', 'utf8');
      plaintext += decipher.final('utf8');

      logger.debug(
        { userId, ciphertextLength: ciphertext.length },
        'Successfully decrypted ciphertext'
      );

      return {
        plaintext,
        userId,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      logger.error(
        { error, userId },
        'Failed to decrypt ciphertext'
      );
      throw error;
    }
  }

  /**
   * Generate a random Data Encryption Key (DEK).
   * Used for initial key generation for new users.
   */
  static generateRandomDEK(): Buffer {
    return randomBytes(KEY_SIZE);
  }
}
