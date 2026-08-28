import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from '@jest/globals';
import { verifyTsaTimestamp } from '../src/crypto/tsa-verify.js';
import type { TsaTimestampInfo } from '../src/gcp/tsa-client.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = path.join(__dirname, 'fixtures');
const REAL_RESPONSE = fs.readFileSync(path.join(FIXTURES_DIR, 'freetsa-response.der'));
const ROOT_CA_PEM = fs.readFileSync(path.join(FIXTURES_DIR, 'freetsa-root-ca.pem'), 'utf-8');
const FIXTURE_INPUT = fs.readFileSync(path.join(FIXTURES_DIR, 'freetsa-fixture-input.txt'), 'utf-8');

// Cross-checked against `openssl ts -reply -in freetsa-response.der -text`'s
// own printed "Time stamp:" line when this fixture was captured
// (2026-08-28), and against `openssl ts -verify`'s independent "Verification: OK"
// -- not just against this test's own code.
const REAL_GEN_TIME = new Date('2026-08-28T15:07:55.000Z');

function realTimestamp(): TsaTimestampInfo {
  return {
    status: 'OBTAINED',
    token: REAL_RESPONSE.toString('base64'),
    timestamp: REAL_GEN_TIME.toISOString(),
    tsaUrl: 'https://freetsa.org/tsr',
    attemptedAt: new Date().toISOString(),
  };
}

describe('verifyTsaTimestamp', () => {
  it('returns VALID with the correct genTime for a real, untampered fixture', async () => {
    const result = await verifyTsaTimestamp(FIXTURE_INPUT, realTimestamp(), ROOT_CA_PEM);

    expect(result).toEqual({ outcome: 'VALID', genTime: REAL_GEN_TIME });
  });

  it('returns ABSENT when no timestamp was ever recorded', async () => {
    const result = await verifyTsaTimestamp(FIXTURE_INPUT, undefined, ROOT_CA_PEM);

    expect(result).toEqual({ outcome: 'ABSENT' });
  });

  it('returns RECORDED_FAILURE when a TSA attempt was made but failed at issuance time', async () => {
    const result = await verifyTsaTimestamp(
      FIXTURE_INPUT,
      { status: 'FAILED', tsaUrl: 'https://freetsa.org/tsr', attemptedAt: new Date().toISOString(), error: 'timeout' },
      ROOT_CA_PEM
    );

    expect(result).toEqual({ outcome: 'RECORDED_FAILURE' });
  });

  it('returns INVALID when the certificate does not match what the token attests to (messageImprint mismatch)', async () => {
    const result = await verifyTsaTimestamp('this is not the fixture input', realTimestamp(), ROOT_CA_PEM);

    expect(result.outcome).toBe('INVALID');
    expect((result as { reason: string }).reason).toContain('messageImprint');
  });

  it('returns INVALID when status is OBTAINED but no token is stored (malformed data)', async () => {
    const result = await verifyTsaTimestamp(
      FIXTURE_INPUT,
      { status: 'OBTAINED', tsaUrl: 'https://freetsa.org/tsr', attemptedAt: new Date().toISOString() },
      ROOT_CA_PEM
    );

    expect(result.outcome).toBe('INVALID');
  });

  it('returns INVALID when the stored token bytes are corrupted/garbage', async () => {
    const result = await verifyTsaTimestamp(
      FIXTURE_INPUT,
      { status: 'OBTAINED', token: Buffer.from('not a real token').toString('base64'), tsaUrl: 'https://freetsa.org/tsr', attemptedAt: new Date().toISOString() },
      ROOT_CA_PEM
    );

    expect(result.outcome).toBe('INVALID');
  });

  it('returns INVALID when the signature is broken (last byte of the token flipped)', async () => {
    const tampered = Buffer.from(REAL_RESPONSE);
    tampered[tampered.length - 1] ^= 0xff;

    const result = await verifyTsaTimestamp(
      FIXTURE_INPUT,
      { status: 'OBTAINED', token: tampered.toString('base64'), tsaUrl: 'https://freetsa.org/tsr', attemptedAt: new Date().toISOString() },
      ROOT_CA_PEM
    );

    expect(result.outcome).toBe('INVALID');
  });

  it('returns INVALID when the pinned root CA does not match the one that actually signed the token', async () => {
    // A structurally different, unrelated self-signed cert -- not FreeTSA's
    // real root, so chain validation must fail.
    const wrongRootPem = `-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIUOWjLmSUiTQwEyt4z4pV4Q2gXtRAwCgYIKoZIzj0EAwIw
EjEQMA4GA1UEAwwHVGVzdCBDQTAeFw0yNjA4MjgwMDAwMDBaFw0zNjA4MjgwMDAw
MDBaMBIxEDAOBgNVBAMMB1Rlc3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AATIeYIekmWDVzhtHRZmMJmDsGP4RaFmZlZ0v6+HKVpzB4XxAf+MSjfe5uYFbdxE
lIf34sK7CkoAG+P3T0iTuU8Fo1MwUTAdBgNVHQ4EFgQUJnI7ecTnhH2WBjOwjE60
ZAsFF6owHwYDVR0jBBgwFoAUJnI7ecTnhH2WBjOwjE60ZAsFF6owDwYDVR0TAQH/
BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiA9x6r63EXbDwB0/H4L1sBqmUvsTr3z
tSF9zXOm7RfkLwIhAOh2WvvEExzTAAmwZ8ZKzq0hLd0IYAV2NsBLE1zqoahL
-----END CERTIFICATE-----`;

    const result = await verifyTsaTimestamp(FIXTURE_INPUT, realTimestamp(), wrongRootPem);

    expect(result.outcome).toBe('INVALID');
  });
});
