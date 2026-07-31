import { jest, describe, it, expect, beforeEach } from '@jest/globals';

// A key created before this app relied on KMS's "primary version" concept
// (i.e. every real signing key that predates rotation support) can have
// versions but no primary at all -- GCP KMS doesn't auto-assign one for
// ASYMMETRIC_SIGN keys the way it does for symmetric keys. This exercises
// getPrimaryVersion()'s self-heal path for exactly that case, against the
// raw @google-cloud/kms client (not the CloudKMSClient wrapper other tests
// mock away), since the self-heal logic lives inside that wrapper.

const KEY_PATH = 'projects/p/locations/r/keyRings/kr/cryptoKeys/kn';

let mockPrimary: { name: string } | undefined;
const mockGetCryptoKey = jest.fn(async () => [{ primary: mockPrimary }]);
const mockUpdateCryptoKeyPrimaryVersion = jest.fn(async () => [{}]);
async function* versionsIterable(versions: { name: string; state: string }[]) {
  for (const v of versions) yield v;
}
let mockVersions: { name: string; state: string }[] = [];
const mockListCryptoKeyVersionsAsync = jest.fn(() => versionsIterable(mockVersions));

await jest.unstable_mockModule('@google-cloud/kms', () => ({
  KeyManagementServiceClient: class {
    getCryptoKey = mockGetCryptoKey;
    updateCryptoKeyPrimaryVersion = mockUpdateCryptoKeyPrimaryVersion;
    listCryptoKeyVersionsAsync = mockListCryptoKeyVersionsAsync;
    cryptoKeyPath(project: string, location: string, keyRing: string, keyName: string): string {
      return `projects/${project}/locations/${location}/keyRings/${keyRing}/cryptoKeys/${keyName}`;
    }
  },
}));

const { CloudKMSClient } = await import('../src/gcp/cloud-kms.js');

describe('CloudKMSClient.getPrimaryVersion', () => {
  beforeEach(() => {
    mockGetCryptoKey.mockClear();
    mockUpdateCryptoKeyPrimaryVersion.mockClear();
    mockListCryptoKeyVersionsAsync.mockClear();
    mockPrimary = undefined;
    mockVersions = [];
  });

  it('returns the primary directly when KMS already has one set', async () => {
    mockPrimary = { name: `${KEY_PATH}/cryptoKeyVersions/2` };
    const client = new CloudKMSClient('p', 'r', 'kr', 'kn');

    const result = await client.getPrimaryVersion(KEY_PATH);

    expect(result).toBe(`${KEY_PATH}/cryptoKeyVersions/2`);
    expect(mockUpdateCryptoKeyPrimaryVersion).not.toHaveBeenCalled();
  });

  it('self-heals by promoting the newest ENABLED version when no primary is set', async () => {
    mockPrimary = undefined;
    mockVersions = [
      { name: `${KEY_PATH}/cryptoKeyVersions/1`, state: 'ENABLED' },
      { name: `${KEY_PATH}/cryptoKeyVersions/10`, state: 'ENABLED' }, // numeric, not lexicographic, sort
      { name: `${KEY_PATH}/cryptoKeyVersions/2`, state: 'ENABLED' },
      { name: `${KEY_PATH}/cryptoKeyVersions/3`, state: 'DESTROYED' },
    ];
    const client = new CloudKMSClient('p', 'r', 'kr', 'kn');

    const result = await client.getPrimaryVersion(KEY_PATH);

    expect(result).toBe(`${KEY_PATH}/cryptoKeyVersions/10`);
    expect(mockUpdateCryptoKeyPrimaryVersion).toHaveBeenCalledWith({
      name: KEY_PATH,
      cryptoKeyVersionId: '10',
    });
  });

  it('throws when no primary is set and no ENABLED version exists to promote', async () => {
    mockPrimary = undefined;
    mockVersions = [{ name: `${KEY_PATH}/cryptoKeyVersions/1`, state: 'DESTROYED' }];
    const client = new CloudKMSClient('p', 'r', 'kr', 'kn');

    await expect(client.getPrimaryVersion(KEY_PATH)).rejects.toThrow('no ENABLED versions to promote');
  });
});
