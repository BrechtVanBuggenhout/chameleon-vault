import { describe, it, expect, jest, beforeEach } from '@jest/globals';
import { ChameleonAesGcm } from '../src/crypto/chameleon-aes-gcm.js';
import { decryptPiiVaultValue } from '../src/services/pii-vault-decryptor.js';

// Mirrors decrypted-views-decrypt.test.ts's fixtures -- this function was
// extracted out of that route file, so the same behavior must hold.
const mockGetKeyForUser = jest.fn(async (userId: string) => {
  if (userId === 'shredded-user') return null;
  if (userId === 'active-user' || userId === 'known-user') {
    return { encryptedDek: Buffer.from('wrapped-dek'), activeDekId: 'v1', encryptionVersion: 'v1' };
  }
  return null;
});
const fakeFirestoreRegistry = { getKeyForUser: mockGetKeyForUser } as any;

const TEST_DEK = Buffer.alloc(32, 7);
const mockDecryptDataEncryptionKey = jest.fn(async () => TEST_DEK);
const fakeKmsClient = { decryptDataEncryptionKey: mockDecryptDataEncryptionKey } as any;

describe('decryptPiiVaultValue', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('returns null for a null or empty ciphertext', async () => {
    expect(await decryptPiiVaultValue(null, 'known-user', 'tenant-a', fakeFirestoreRegistry, fakeKmsClient)).toBeNull();
    expect(await decryptPiiVaultValue('', 'known-user', 'tenant-a', fakeFirestoreRegistry, fakeKmsClient)).toBeNull();
  });

  it('returns null for a null userId', async () => {
    expect(await decryptPiiVaultValue('v1:iv:ct', null, 'tenant-a', fakeFirestoreRegistry, fakeKmsClient)).toBeNull();
  });

  it('returns null for a malformed (< 3 part) ciphertext', async () => {
    expect(await decryptPiiVaultValue('v1:onlytwoparts', 'known-user', 'tenant-a', fakeFirestoreRegistry, fakeKmsClient)).toBeNull();
  });

  it('returns null for a shredded user (no encryptedDek)', async () => {
    const { ivB64, ciphertextB64 } = ChameleonAesGcm.encrypt('jane@example.com', 'shredded-user', TEST_DEK);
    const result = await decryptPiiVaultValue(
      `v1:${ivB64}:${ciphertextB64}`,
      'shredded-user',
      'tenant-a',
      fakeFirestoreRegistry,
      fakeKmsClient
    );
    expect(result).toBeNull();
    expect(mockDecryptDataEncryptionKey).not.toHaveBeenCalled();
  });

  it('returns null (not a thrown error) when the ciphertext does not actually decrypt', async () => {
    const result = await decryptPiiVaultValue(
      'v1:bm90LWFuLWl2Cg==:bm90LXJlYWwtY2lwaGVydGV4dA==',
      'active-user',
      'tenant-a',
      fakeFirestoreRegistry,
      fakeKmsClient
    );
    expect(result).toBeNull();
  });

  it('decrypts a real ciphertext end to end', async () => {
    const { ivB64, ciphertextB64 } = ChameleonAesGcm.encrypt('jane@example.com', 'known-user', TEST_DEK);
    const result = await decryptPiiVaultValue(
      `v1:${ivB64}:${ciphertextB64}`,
      'known-user',
      'tenant-a',
      fakeFirestoreRegistry,
      fakeKmsClient
    );
    expect(result).toBe('jane@example.com');
    expect(mockGetKeyForUser).toHaveBeenCalledWith('known-user', 'tenant-a', 'v1');
  });

  it('defaults tenantId to "default-tenant" when null', async () => {
    const { ivB64, ciphertextB64 } = ChameleonAesGcm.encrypt('jane@example.com', 'known-user', TEST_DEK);
    await decryptPiiVaultValue(`v1:${ivB64}:${ciphertextB64}`, 'known-user', null, fakeFirestoreRegistry, fakeKmsClient);
    expect(mockGetKeyForUser).toHaveBeenCalledWith('known-user', 'default-tenant', 'v1');
  });
});
