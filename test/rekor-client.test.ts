import { jest, describe, it, expect, beforeEach } from '@jest/globals';

const mockPost = jest.fn();
await jest.unstable_mockModule('axios', () => ({
  default: { post: mockPost },
}));

const { RekorClient } = await import('../src/gcp/rekor-client.js');
const { CloudKMSClient } = await import('../src/gcp/cloud-kms.js');

describe('RekorClient.publishCertificateHash', () => {
  let mockKmsClient: { asymmetricSign: jest.Mock; getPublicKey: jest.Mock };
  let getSigningKeyVersionPath: jest.Mock;

  beforeEach(() => {
    mockPost.mockReset();
    mockKmsClient = {
      asymmetricSign: jest.fn().mockResolvedValue('ZmFrZS1zaWduYXR1cmU'), // base64url, no padding
      getPublicKey: jest.fn().mockResolvedValue('-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----'),
    };
    getSigningKeyVersionPath = jest.fn().mockResolvedValue('projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1');
  });

  it('submits a hashedrekord entry with base64 (not base64url) signature and PEM-encoded public key', async () => {
    mockPost.mockResolvedValue({
      status: 201,
      data: {
        'entry-uuid-123': { logIndex: 42 },
      },
    });

    const client = new RekorClient(
      'https://rekor.sigstore.dev',
      mockKmsClient as unknown as InstanceType<typeof CloudKMSClient>,
      getSigningKeyVersionPath as unknown as () => Promise<string>
    );

    const result = await client.publishCertificateHash('abc123', 'def456');

    expect(result).toEqual({
      status: 'PUBLISHED',
      entryUuid: 'entry-uuid-123',
      logIndex: 42,
      rekorUrl: 'https://rekor.sigstore.dev',
      attemptedAt: expect.any(String),
    });

    expect(mockPost).toHaveBeenCalledTimes(1);
    const [url, body] = mockPost.mock.calls[0] as [string, any];
    expect(url).toBe('https://rekor.sigstore.dev/api/v1/log/entries');
    expect(body.kind).toBe('hashedrekord');
    expect(body.spec.data.hash.algorithm).toBe('sha256');

    // Signature must be re-encoded from base64url to standard base64 --
    // Rekor's API rejects base64url. KMS's asymmetricSign returns
    // 'ZmFrZS1zaWduYXR1cmU' (base64url, no padding); confirm it survived the
    // conversion rather than being passed through unchanged.
    expect(body.spec.signature.content).toBe(Buffer.from('ZmFrZS1zaWduYXR1cmU', 'base64url').toString('base64'));

    // Public key must be base64-of-the-PEM-string, not the raw PEM.
    expect(body.spec.signature.publicKey.content).toBe(
      Buffer.from('-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----').toString('base64')
    );

    // The payload actually signed/hashed must be the canonical
    // {certificateHash, previousCertificateHash} shape -- never tenantId or
    // userId, matching the same principle as the existing by-hash lookup.
    const [signedPayload] = mockKmsClient.asymmetricSign.mock.calls[0] as [string, string];
    expect(JSON.parse(signedPayload)).toEqual({ certificateHash: 'abc123', previousCertificateHash: 'def456' });
  });

  it('handles previousCertificateHash being null (first certificate in a chain)', async () => {
    mockPost.mockResolvedValue({ status: 201, data: { uuid1: { logIndex: 1 } } });
    const client = new RekorClient(
      'https://rekor.sigstore.dev',
      mockKmsClient as unknown as InstanceType<typeof CloudKMSClient>,
      getSigningKeyVersionPath as unknown as () => Promise<string>
    );

    await client.publishCertificateHash('abc123', null);

    const [signedPayload] = mockKmsClient.asymmetricSign.mock.calls[0] as [string, string];
    expect(JSON.parse(signedPayload)).toEqual({ certificateHash: 'abc123', previousCertificateHash: null });
  });

  it('returns FAILED, never throws, on a non-201 response', async () => {
    mockPost.mockResolvedValue({ status: 400, data: { message: 'verifying signature: crypto/rsa: verification error' } });
    const client = new RekorClient(
      'https://rekor.sigstore.dev',
      mockKmsClient as unknown as InstanceType<typeof CloudKMSClient>,
      getSigningKeyVersionPath as unknown as () => Promise<string>
    );

    const result = await client.publishCertificateHash('abc123', null);

    expect(result.status).toBe('FAILED');
    expect(result.error).toBe('HTTP 400');
  });

  it('returns FAILED, never throws, when the request itself throws (network error)', async () => {
    mockPost.mockRejectedValue(new Error('ECONNREFUSED'));
    const client = new RekorClient(
      'https://rekor.sigstore.dev',
      mockKmsClient as unknown as InstanceType<typeof CloudKMSClient>,
      getSigningKeyVersionPath as unknown as () => Promise<string>
    );

    const result = await client.publishCertificateHash('abc123', null);

    expect(result.status).toBe('FAILED');
    expect(result.error).toBe('ECONNREFUSED');
  });

  it('returns FAILED, never throws, when KMS signing itself throws', async () => {
    mockKmsClient.asymmetricSign.mockRejectedValue(new Error('KMS unavailable'));
    const client = new RekorClient(
      'https://rekor.sigstore.dev',
      mockKmsClient as unknown as InstanceType<typeof CloudKMSClient>,
      getSigningKeyVersionPath as unknown as () => Promise<string>
    );

    const result = await client.publishCertificateHash('abc123', null);

    expect(result.status).toBe('FAILED');
    expect(result.error).toBe('KMS unavailable');
    expect(mockPost).not.toHaveBeenCalled();
  });
});

describe('RekorClient.getPublicKeyPem', () => {
  it('resolves the signing key version path and returns its public key PEM', async () => {
    const mockKmsClient = {
      asymmetricSign: jest.fn(),
      getPublicKey: jest.fn().mockResolvedValue('-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----'),
    };
    const getSigningKeyVersionPath = jest.fn().mockResolvedValue('projects/p/.../cryptoKeyVersions/3');

    const client = new RekorClient(
      'https://rekor.sigstore.dev',
      mockKmsClient as unknown as InstanceType<typeof CloudKMSClient>,
      getSigningKeyVersionPath as unknown as () => Promise<string>
    );

    const pem = await client.getPublicKeyPem();

    expect(pem).toBe('-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----');
    expect(mockKmsClient.getPublicKey).toHaveBeenCalledWith('projects/p/.../cryptoKeyVersions/3');
  });
});
