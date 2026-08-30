import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from 'jose';

export class UnauthorizedError extends Error {}

// Injectable, same shape as SigningKmsClient/CertificateSignerFirestoreClient
// -- lets tests pass a real local JWKS (jose's createLocalJWKSet, built from
// a throwaway test keypair, no network involved) instead of module-mocking
// `jose` itself. Module-mocking doesn't work cleanly here: this package
// installs its own node_modules/jose for its standalone build, resolved
// ahead of the repo root's copy for any import inside this directory, so a
// jest.unstable_mockModule('jose', ...) would mock a different resolved
// module instance than the one this file actually imports.
export interface IdTokenVerifier {
  verify(authorizationHeader: string | undefined, expectedAudience: string, expectedCallerEmail: string): Promise<void>;
}

/**
 * Verifies a caller-presented Google-signed ID token (mirrors Cloud Run's
 * own `run.invoker` service-to-service auth pattern -- see
 * chameleon-paper/TEE_ATTESTATION_PLAN.md, Phase 2's networking decision
 * for why this replaces network-level isolation rather than supplementing
 * it). Checks issuer, audience, expiry (all via jwtVerify), and that the
 * token's subject is the exact expected caller identity -- an otherwise
 * validly-signed token minted for some other Google Cloud principal must
 * not be accepted.
 */
export class GoogleIdTokenVerifier implements IdTokenVerifier {
  // Same jose JWKS-verification pattern already used by
  // scripts/verify-cert.ts for certificate JWTs -- reused here for a
  // different purpose: verifying HTTP callers instead of issued certs.
  // Defaults to Google's real, live JWKS; tests inject a local one instead.
  constructor(
    private readonly jwks: JWTVerifyGetKey = createRemoteJWKSet(new URL('https://www.googleapis.com/oauth2/v3/certs'))
  ) {}

  async verify(authorizationHeader: string | undefined, expectedAudience: string, expectedCallerEmail: string): Promise<void> {
    if (!authorizationHeader?.startsWith('Bearer ')) {
      throw new UnauthorizedError('Missing bearer token');
    }
    const token = authorizationHeader.slice('Bearer '.length);

    let payload;
    try {
      ({ payload } = await jwtVerify(token, this.jwks, {
        issuer: ['accounts.google.com', 'https://accounts.google.com'],
        audience: expectedAudience,
      }));
    } catch (err) {
      throw new UnauthorizedError(`Invalid ID token: ${(err as Error).message}`);
    }

    if (payload.email !== expectedCallerEmail || payload.email_verified !== true) {
      throw new UnauthorizedError(`Unexpected caller identity: ${String(payload.email)}`);
    }
  }
}
