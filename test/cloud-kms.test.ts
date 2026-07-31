import { jest, describe, it, expect, beforeEach } from '@jest/globals';

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

await jest.unstable_mockModule('@google-cloud/kms', () => ({
  KeyManagementServiceClient: class {
    listCryptoKeyVersionsAsync = mockListCryptoKeyVersionsAsync;
    cryptoKeyPath(project: string, location: string, keyRing: string, keyName: string): string {
      return `projects/${project}/locations/${location}/keyRings/${keyRing}/cryptoKeys/${keyName}`;
    }
  },
}));

const { CloudKMSClient } = await import('../src/gcp/cloud-kms.js');

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
