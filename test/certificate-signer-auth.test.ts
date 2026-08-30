import { describe, it, expect, beforeAll } from '@jest/globals';
import { generateKeyPair, exportJWK, createLocalJWKSet, SignJWT, type KeyLike } from 'jose';

import { GoogleIdTokenVerifier, UnauthorizedError } from '../src/certificate-signer/auth.js';

// Real crypto throughout, no module mocking -- a throwaway local keypair
// and jose's createLocalJWKSet stand in for Google's real, remote JWKS, so
// the actual jwtVerify call path (issuer/audience/expiry checks included)
// runs for real instead of being mocked away. See auth.ts's own comment for
// why module-mocking `jose` doesn't work cleanly for this package.
describe('GoogleIdTokenVerifier.verify', () => {
  const AUDIENCE = 'https://certificate-signer.example.internal';
  const CALLER_EMAIL = 'key-vault@chameleon-dev.iam.gserviceaccount.com';
  const KID = 'test-key-1';

  let verifier: GoogleIdTokenVerifier;
  let privateKey: KeyLike;

  beforeAll(async () => {
    const { publicKey, privateKey: sk } = await generateKeyPair('ES256');
    privateKey = sk;
    const jwk = await exportJWK(publicKey);
    jwk.kid = KID;
    jwk.alg = 'ES256';
    const localJwks = createLocalJWKSet({ keys: [jwk] });
    verifier = new GoogleIdTokenVerifier(localJwks);
  });

  async function signToken(overrides: {
    email?: string;
    email_verified?: boolean;
    audience?: string;
    issuer?: string;
    expiresIn?: string;
  } = {}): Promise<string> {
    return new SignJWT({
      email: overrides.email ?? CALLER_EMAIL,
      email_verified: overrides.email_verified ?? true,
    })
      .setProtectedHeader({ alg: 'ES256', kid: KID })
      .setIssuer(overrides.issuer ?? 'https://accounts.google.com')
      .setAudience(overrides.audience ?? AUDIENCE)
      .setIssuedAt()
      .setExpirationTime(overrides.expiresIn ?? '5m')
      .sign(privateKey);
  }

  it('rejects a missing Authorization header', async () => {
    await expect(verifier.verify(undefined, AUDIENCE, CALLER_EMAIL)).rejects.toThrow(UnauthorizedError);
  });

  it('rejects a non-Bearer Authorization header', async () => {
    await expect(verifier.verify('Basic abc123', AUDIENCE, CALLER_EMAIL)).rejects.toThrow(UnauthorizedError);
  });

  it('rejects a token signed for the wrong audience', async () => {
    const token = await signToken({ audience: 'https://someone-elses-service.example.internal' });
    await expect(verifier.verify(`Bearer ${token}`, AUDIENCE, CALLER_EMAIL)).rejects.toThrow(UnauthorizedError);
  });

  it('rejects a token from the wrong issuer', async () => {
    const token = await signToken({ issuer: 'https://not-google.example.com' });
    await expect(verifier.verify(`Bearer ${token}`, AUDIENCE, CALLER_EMAIL)).rejects.toThrow(UnauthorizedError);
  });

  it('rejects an expired token', async () => {
    const token = await signToken({ expiresIn: '-1m' });
    await expect(verifier.verify(`Bearer ${token}`, AUDIENCE, CALLER_EMAIL)).rejects.toThrow(UnauthorizedError);
  });

  it('rejects a validly-signed token whose email does not match the expected caller', async () => {
    const token = await signToken({ email: 'someone-else@another-project.iam.gserviceaccount.com' });
    await expect(verifier.verify(`Bearer ${token}`, AUDIENCE, CALLER_EMAIL)).rejects.toThrow(UnauthorizedError);
  });

  it('rejects a token with email_verified: false even if the email matches', async () => {
    const token = await signToken({ email_verified: false });
    await expect(verifier.verify(`Bearer ${token}`, AUDIENCE, CALLER_EMAIL)).rejects.toThrow(UnauthorizedError);
  });

  it('rejects a token signed by a key not present in the JWKS (forged kid aside, wrong signer)', async () => {
    const { privateKey: otherKey } = await generateKeyPair('ES256');
    const token = await new SignJWT({ email: CALLER_EMAIL, email_verified: true })
      .setProtectedHeader({ alg: 'ES256', kid: KID })
      .setIssuer('https://accounts.google.com')
      .setAudience(AUDIENCE)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(otherKey);
    await expect(verifier.verify(`Bearer ${token}`, AUDIENCE, CALLER_EMAIL)).rejects.toThrow(UnauthorizedError);
  });

  it('accepts a validly-signed token from the exact expected caller', async () => {
    const token = await signToken();
    await expect(verifier.verify(`Bearer ${token}`, AUDIENCE, CALLER_EMAIL)).resolves.toBeUndefined();
  });
});
