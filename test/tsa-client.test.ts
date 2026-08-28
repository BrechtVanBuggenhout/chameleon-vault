import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';
import { jest, describe, it, expect, beforeEach } from '@jest/globals';
import { AsnConvert } from '@peculiar/asn1-schema';
import { TimeStampResp, PKIStatus, PKIStatusInfo } from '@peculiar/asn1-tsp';

const mockPost = jest.fn();
await jest.unstable_mockModule('axios', () => ({
  default: { post: mockPost },
}));

// Node's built-in `crypto` is a frozen ESM module namespace under Jest's
// experimental VM modules -- jest.spyOn can't assign to it directly (throws
// "Cannot assign to property... of Module"). Mocked the same way axios is
// above instead: real behavior preserved for everything (createHash, etc.),
// only randomBytes made overridable per-test, needed for one test below
// that has to reproduce the exact nonce baked into a real captured fixture.
const actualCrypto = await import('crypto');
const randomBytesMock = jest.fn(actualCrypto.randomBytes);
await jest.unstable_mockModule('crypto', () => ({ ...actualCrypto, randomBytes: randomBytesMock }));

const crypto = await import('crypto');
const { TsaClient } = await import('../src/gcp/tsa-client.js');

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = path.join(__dirname, 'fixtures');
const REAL_RESPONSE = fs.readFileSync(path.join(FIXTURES_DIR, 'freetsa-response.der'));
const FIXTURE_INPUT = fs.readFileSync(path.join(FIXTURES_DIR, 'freetsa-fixture-input.txt'));
// The exact hash the real fixture's TSTInfo.messageImprint carries --
// confirmed via a spike script against the real fixture before this test
// existed. TsaClient itself also cross-checks this internally (see its own
// "imprintMatches" check), so a wrong hash here would make this test fail
// with a clear "messageImprint mismatch" rather than a silent false pass.
const REAL_FIXTURE_HASH_HEX = crypto.createHash('sha256').update(FIXTURE_INPUT).digest('hex');

describe('TsaClient.requestTimestamp', () => {
  let client: InstanceType<typeof TsaClient>;

  beforeEach(() => {
    mockPost.mockReset();
    randomBytesMock.mockClear();
    client = new TsaClient('https://freetsa.org/tsr');
  });

  it('returns OBTAINED with the real captured token when the TSA grants the request', async () => {
    mockPost.mockResolvedValue({ status: 200, data: REAL_RESPONSE });

    // The real fixture has a fixed nonce baked in from when it was
    // actually captured against FreeTSA (0x3A035458ED62D2E8). TsaClient
    // generates and checks a fresh nonce on every call as a defensive
    // replay check, so this one test has to make crypto.randomBytes
    // return that same real value for the round-trip check to pass --
    // otherwise this is indistinguishable from testing against a stale
    // response for a different request, which the nonce check exists to
    // catch.
    randomBytesMock.mockReturnValueOnce(Buffer.from('3a035458ed62d2e8', 'hex') as never);

    const result = await client.requestTimestamp(REAL_FIXTURE_HASH_HEX);

    expect(result.status).toBe('OBTAINED');
    expect(result.token).toBe(REAL_RESPONSE.toString('base64'));
    expect(result.timestamp).toBe('2026-08-28T15:07:55.000Z');
    expect(result.tsaUrl).toBe('https://freetsa.org/tsr');
  });

  it('sends the correct content-type headers and a bounded timeout', async () => {
    mockPost.mockResolvedValue({ status: 200, data: REAL_RESPONSE });

    await client.requestTimestamp(REAL_FIXTURE_HASH_HEX);

    expect(mockPost).toHaveBeenCalledWith(
      'https://freetsa.org/tsr',
      expect.any(Buffer),
      expect.objectContaining({
        headers: expect.objectContaining({
          'Content-Type': 'application/timestamp-query',
        }),
        timeout: 5_000,
        responseType: 'arraybuffer',
      })
    );
  });

  it('returns FAILED, never throws, on a non-200 response', async () => {
    mockPost.mockResolvedValue({ status: 503, data: Buffer.alloc(0) });

    const result = await client.requestTimestamp(REAL_FIXTURE_HASH_HEX);

    expect(result.status).toBe('FAILED');
    expect(result.error).toContain('503');
  });

  it('returns FAILED, never throws, when the request itself throws (network error)', async () => {
    mockPost.mockRejectedValue(new Error('ECONNRESET'));

    const result = await client.requestTimestamp(REAL_FIXTURE_HASH_HEX);

    expect(result.status).toBe('FAILED');
    expect(result.error).toContain('ECONNRESET');
  });

  it('returns FAILED, never throws, on garbage bytes that fail to parse', async () => {
    mockPost.mockResolvedValue({ status: 200, data: Buffer.from('not a valid TimeStampResp') });

    const result = await client.requestTimestamp(REAL_FIXTURE_HASH_HEX);

    expect(result.status).toBe('FAILED');
  });

  it('returns FAILED on a hand-crafted rejection status', async () => {
    const rejected = new TimeStampResp({
      status: new PKIStatusInfo({ status: PKIStatus.rejection }),
    });
    const rejectedBytes = Buffer.from(AsnConvert.serialize(rejected));
    mockPost.mockResolvedValue({ status: 200, data: rejectedBytes });

    const result = await client.requestTimestamp(REAL_FIXTURE_HASH_HEX);

    expect(result.status).toBe('FAILED');
    expect(result.error).toContain('PKIStatus');
  });

  it('returns FAILED if the response messageImprint does not match what was requested', async () => {
    mockPost.mockResolvedValue({ status: 200, data: REAL_RESPONSE });

    // A different hash than the one the real fixture actually attests to.
    const wrongHash = crypto.createHash('sha256').update('something else entirely').digest('hex');
    const result = await client.requestTimestamp(wrongHash);

    expect(result.status).toBe('FAILED');
    expect(result.error).toContain('messageImprint');
  });
});
