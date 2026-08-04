import { FirestoreRegistry } from '../gcp/firestore-registry.js';
import { CloudKMSClient } from '../gcp/cloud-kms.js';
import { ChameleonAesGcm } from '../crypto/chameleon-aes-gcm.js';
import { createLogger } from '../logging/index.js';

const logger = createLogger('pii-vault-decryptor');

/**
 * Decrypts one pii_vault ciphertext -- shared by the decrypted-views batch-
 * decrypt route (called from a BigQuery remote function, many rows at once)
 * and the ad-hoc single-lookup decrypt route (one row, on demand). Extracted
 * so both stay on the exact same real crypto path rather than drifting.
 *
 * rawCiphertext is pii_vault.encrypted_value's on-disk format
 * (chameleon-data-pipelines' pii_vault_sync.py _encrypt_field):
 * key_id:iv_b64:ciphertext_b64 -- three parts, not two. Randomized AES-GCM
 * (ChameleonAesGcm), not the deterministic-IV scheme DeterministicAES uses;
 * that class only ever matches Key Vault's own demoted /encrypt-/decrypt
 * routes, never production ciphertext written by the pipeline.
 *
 * A failed decrypt (shredded key, malformed ciphertext) returns null rather
 * than throwing -- the caller decides what null means for its own response
 * shape (a batch row, or a single lookup result).
 */
export async function decryptPiiVaultValue(
  rawCiphertext: string | null,
  userId: string | null,
  tenantId: string | null,
  firestoreRegistry: FirestoreRegistry,
  dekKmsClient: CloudKMSClient
): Promise<string | null> {
  if (!rawCiphertext || !userId) return null;

  const parts = rawCiphertext.split(':');
  if (parts.length < 3) return null;
  const [keyVersionId, ivB64] = parts;
  const ciphertextB64 = parts.slice(2).join(':');
  if (!keyVersionId || !ivB64 || !ciphertextB64) return null;

  const keyData = await firestoreRegistry.getKeyForUser(userId, tenantId || 'default-tenant', keyVersionId);
  if (!keyData || !keyData.encryptedDek) return null;

  try {
    const dek = await dekKmsClient.decryptDataEncryptionKey(keyData.encryptedDek, tenantId || 'default-tenant');
    return ChameleonAesGcm.decrypt(ivB64, ciphertextB64, userId, dek);
  } catch (error) {
    logger.warn({ error, userId }, 'Failed to decrypt a pii_vault value');
    return null;
  }
}
