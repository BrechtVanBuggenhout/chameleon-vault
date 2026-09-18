import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';

// GCP KMS has no "primary version" concept for ASYMMETRIC_SIGN keys --
// UpdateCryptoKeyPrimaryVersion rejects it outright (FAILED_PRECONDITION).
// getNewestEnabledVersion() is what stands in for "current" instead: KMS
// assigns version ids as a strictly increasing integer sequence per key, so
// the newest ENABLED version is unambiguous with no separate pointer to
// keep in sync. This exercises that against the raw @google-cloud/kms
// client (not the CloudKMSClient wrapper other tests mock away), since the
// logic lives inside that wrapper.

const KEY_PATH = 'projects/p/locations/r/keyRings/kr/cryptoKeys/kn';

async function* versionsIterable(versions: { name: string; state: string }[]): AsyncGenerator<{ name: string; state: string }> {
  for (const v of versions) yield v;
}
let mockVersions: { name: string; state: string }[] = [];
const mockListCryptoKeyVersionsAsync = jest.fn(() => versionsIterable(mockVersions));
const mockDecrypt = jest.fn();
const mockEncrypt = jest.fn();

await jest.unstable_mockModule('@google-cloud/kms', () => ({
  KeyManagementServiceClient: class {
    listCryptoKeyVersionsAsync = mockListCryptoKeyVersionsAsync;
    decrypt = mockDecrypt;
    encrypt = mockEncrypt;
    cryptoKeyPath(project: string, location: string, keyRing: string, keyName: string): string {
      return `projects/${project}/locations/${location}/keyRings/${keyRing}/cryptoKeys/${keyName}`;
    }
  },
}));

const { CloudKMSClient } = await import('../src/gcp/cloud-kms.js');
const { DeterministicAES } = await import('../src/crypto/deterministic-aes.js');

describe('CloudKMSClient.getNewestEnabledVersion', () => {
  beforeEach(() => {
    mockListCryptoKeyVersionsAsync.mockClear();
    mockVersions = [];
  });

  it('returns the numerically newest ENABLED version, not the lexicographically last', async () => {
    mockVersions = [
      { name: `${KEY_PATH}/cryptoKeyVersions/1`, state: 'ENABLED' },
      { name: `${KEY_PATH}/cryptoKeyVersions/10`, state: 'ENABLED' },
      { name: `${KEY_PATH}/cryptoKeyVersions/2`, state: 'ENABLED' },
    ];
    const client = new CloudKMSClient('p', 'r', 'kr', 'kn');

    const result = await client.getNewestEnabledVersion(KEY_PATH);

    expect(result).toBe(`${KEY_PATH}/cryptoKeyVersions/10`);
  });

  it('ignores non-ENABLED versions (e.g. a disabled newest version falls back to the next one)', async () => {
    mockVersions = [
      { name: `${KEY_PATH}/cryptoKeyVersions/1`, state: 'ENABLED' },
      { name: `${KEY_PATH}/cryptoKeyVersions/2`, state: 'ENABLED' },
      { name: `${KEY_PATH}/cryptoKeyVersions/3`, state: 'DISABLED' },
    ];
    const client = new CloudKMSClient('p', 'r', 'kr', 'kn');

    const result = await client.getNewestEnabledVersion(KEY_PATH);

    expect(result).toBe(`${KEY_PATH}/cryptoKeyVersions/2`);
  });

  it('throws when there are no ENABLED versions at all', async () => {
    mockVersions = [{ name: `${KEY_PATH}/cryptoKeyVersions/1`, state: 'DESTROYED' }];
    const client = new CloudKMSClient('p', 'r', 'kr', 'kn');

    await expect(client.getNewestEnabledVersion(KEY_PATH)).rejects.toThrow('no ENABLED versions');
  });
});

// DEK memory hygiene (CSC699 Week 1's A14 finding): a plaintext DEK must not
// sit any longer than necessary as a plain, GC-managed Buffer. These tests
// check what this code can actually control -- the gRPC client's own
// returned buffer and this code's own intermediate copy both get zeroed,
// and the real result handed to callers is a KeyObject, not a Buffer.
// They can't prove the underlying key material is unreachable everywhere in
// the process (V8 GC compaction, OpenSSL's own internal handling) -- only
// that this code no longer leaves an unzeroed, application-visible copy
// lying around.
describe('CloudKMSClient.decryptDataEncryptionKey', () => {
  beforeEach(() => {
    mockDecrypt.mockClear();
  });

  it('returns a KeyObject wrapping the real DEK bytes, not a Buffer', async () => {
    const realDek = Buffer.from('11'.repeat(32), 'hex');
    mockDecrypt.mockResolvedValue([{ plaintext: new Uint8Array(realDek) }]);
    const client = new CloudKMSClient('p', 'r', 'kr', 'kn');

    const result = await client.decryptDataEncryptionKey(Buffer.from('ciphertext'));

    expect(Buffer.isBuffer(result)).toBe(false);
    expect(result.type).toBe('secret');
    expect(result.symmetricKeySize).toBe(32);
    // export() on a secret KeyObject returns the raw key bytes -- confirms
    // the wrap actually carries the real DEK, not something derived wrong.
    expect(result.export().equals(realDek)).toBe(true);
  });

  it('zeroes the gRPC client\'s own returned buffer after copying it', async () => {
    const returnedPlaintext = new Uint8Array(Buffer.from('22'.repeat(32), 'hex'));
    mockDecrypt.mockResolvedValue([{ plaintext: returnedPlaintext }]);
    const client = new CloudKMSClient('p', 'r', 'kr', 'kn');

    await client.decryptDataEncryptionKey(Buffer.from('ciphertext'));

    expect(returnedPlaintext.every(byte => byte === 0)).toBe(true);
  });

  it('throws, without wrapping anything, when Cloud KMS returns no plaintext', async () => {
    mockDecrypt.mockResolvedValue([{}]);
    const client = new CloudKMSClient('p', 'r', 'kr', 'kn');

    await expect(client.decryptDataEncryptionKey(Buffer.from('ciphertext'))).rejects.toThrow('no plaintext returned');
  });
});

describe('CloudKMSClient.generateAndEncryptDek', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('zeroes its locally-generated plaintext DEK after encrypting it, on success', async () => {
    const generatedDek = Buffer.from('33'.repeat(32), 'hex');
    jest.spyOn(DeterministicAES, 'generateRandomDEK').mockReturnValue(generatedDek);
    mockEncrypt.mockResolvedValue([{ ciphertext: Buffer.from('wrapped-dek') }]);
    const client = new CloudKMSClient('p', 'r', 'kr', 'kn');

    const result = await client.generateAndEncryptDek();

    expect(result).toEqual(Buffer.from('wrapped-dek'));
    expect(generatedDek.every(byte => byte === 0)).toBe(true);
  });

  it('still zeroes the locally-generated plaintext DEK when the KMS encrypt call fails', async () => {
    const generatedDek = Buffer.from('44'.repeat(32), 'hex');
    jest.spyOn(DeterministicAES, 'generateRandomDEK').mockReturnValue(generatedDek);
    mockEncrypt.mockRejectedValue(new Error('KMS unavailable'));
    const client = new CloudKMSClient('p', 'r', 'kr', 'kn');

    await expect(client.generateAndEncryptDek()).rejects.toThrow('Failed to generate and encrypt new DEK');

    expect(generatedDek.every(byte => byte === 0)).toBe(true);
  });
});
