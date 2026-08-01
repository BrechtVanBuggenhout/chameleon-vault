import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';

const KEY_SIZE = 32; // 256 bits
const AUTH_TAG_SIZE = 16; // 128 bits for GCM
const ALGORITHM = 'aes-256-gcm';

export interface ChameleonEncryptionResult {
  ivB64: string;
  ciphertextB64: string;
}

/**
 * Matches the on-disk ciphertext format chameleon-data-pipelines' Python
 * side actually writes for raw_users and pii_vault (ChameleonCrypto in
 * app/core/crypto.py, packaged into `key_id:iv_b64:ciphertext_b64` by
 * pii_vault_sync.py's _encrypt_field / ingestion.py's own copy of it):
 * randomized AES-256-GCM with a random per-value 12-byte IV (not derived
 * from userId, unlike DeterministicAES), AAD = userId, GCM tag appended to
 * the ciphertext.
 *
 * This class only ever sees the iv/ciphertext halves of that bundle -- the
 * leading key_id segment is parsed by the caller and used for DEK lookup,
 * not passed in here.
 */
export class ChameleonAesGcm {
  static encrypt(plaintext: string, userId: string, dek: Buffer): ChameleonEncryptionResult {
    if (dek.length !== KEY_SIZE) {
      throw new Error(`DEK must be ${KEY_SIZE} bytes, got ${dek.length}`);
    }

    const iv = randomBytes(12);
    const aad = Buffer.from(userId);

    const cipher = createCipheriv(ALGORITHM, dek, iv);
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return {
      ivB64: iv.toString('base64'),
      ciphertextB64: Buffer.concat([ciphertext, authTag]).toString('base64'),
    };
  }

  static decrypt(ivB64: string, ciphertextB64: string, userId: string, dek: Buffer): string {
    if (dek.length !== KEY_SIZE) {
      throw new Error(`DEK must be ${KEY_SIZE} bytes, got ${dek.length}`);
    }

    const iv = Buffer.from(ivB64, 'base64');
    const combined = Buffer.from(ciphertextB64, 'base64');
    if (combined.length < AUTH_TAG_SIZE) {
      throw new Error('Invalid ciphertext: too short');
    }

    const ciphertext = combined.subarray(0, combined.length - AUTH_TAG_SIZE);
    const authTag = combined.subarray(combined.length - AUTH_TAG_SIZE);
    const aad = Buffer.from(userId);

    const decipher = createDecipheriv(ALGORITHM, dek, iv);
    decipher.setAAD(aad);
    decipher.setAuthTag(authTag);

    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return plaintext.toString('utf8');
  }
}
