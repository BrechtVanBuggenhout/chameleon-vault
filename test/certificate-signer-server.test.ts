import * as http from 'http';
import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';

import { createServer } from '../src/certificate-signer/server.js';
import { CertificateSigner } from '../src/certificate-signer/sign.js';
import { IdTokenVerifier, UnauthorizedError } from '../src/certificate-signer/auth.js';

const CONFIG = { idTokenAudience: 'aud', allowedCallerEmail: 'caller@example.com' };

function listen(server: http.Server): Promise<number> {
  return new Promise((resolve) => {
    server.listen(0, () => {
      const address = server.address();
      resolve(typeof address === 'object' && address ? address.port : 0);
    });
  });
}

describe('certificate-signer HTTP server', () => {
  let mockSigner: { generateClaims: jest.Mock; signClaims: jest.Mock; invalidateSigningKeyCache: jest.Mock };
  let mockVerifier: { verify: jest.Mock };
  let server: http.Server;
  let port: number;

  beforeEach(async () => {
    mockSigner = {
      generateClaims: jest.fn(),
      signClaims: jest.fn(),
      invalidateSigningKeyCache: jest.fn(),
    };
    mockVerifier = { verify: jest.fn<IdTokenVerifier['verify']>().mockResolvedValue(undefined) };
    server = createServer(
      mockSigner as unknown as InstanceType<typeof CertificateSigner>,
      mockVerifier as unknown as IdTokenVerifier,
      CONFIG
    );
    port = await listen(server);
  });

  afterEach(() => {
    server.close();
  });

  it('serves /healthz without requiring auth', async () => {
    const res = await fetch(`http://localhost:${port}/healthz`);
    expect(res.status).toBe(200);
    expect(mockVerifier.verify).not.toHaveBeenCalled();
  });

  it('rejects every other route with 401 when auth fails, before touching the signer', async () => {
    mockVerifier.verify.mockRejectedValue(new UnauthorizedError('nope'));

    const res = await fetch(`http://localhost:${port}/v1/generate-claims`, { method: 'POST', body: '{}' });

    expect(res.status).toBe(401);
    expect(mockSigner.generateClaims).not.toHaveBeenCalled();
  });

  it('passes the Authorization header and configured audience/caller through to the verifier', async () => {
    await fetch(`http://localhost:${port}/v1/generate-claims`, {
      method: 'POST',
      headers: { Authorization: 'Bearer test-token' },
      body: '{}',
    });

    expect(mockVerifier.verify).toHaveBeenCalledWith('Bearer test-token', CONFIG.idTokenAudience, CONFIG.allowedCallerEmail);
  });

  it('POST /v1/generate-claims calls signer.generateClaims with the parsed body and returns its result', async () => {
    mockSigner.generateClaims.mockResolvedValue({ sub: 'user-1' });

    const res = await fetch(`http://localhost:${port}/v1/generate-claims`, {
      method: 'POST',
      body: JSON.stringify({ userId: 'user-1' }),
    });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ sub: 'user-1' });
    expect(mockSigner.generateClaims).toHaveBeenCalledWith({ userId: 'user-1' });
  });

  it('POST /v1/sign-claims calls signer.signClaims and returns its result', async () => {
    mockSigner.signClaims.mockResolvedValue({ certificate: 'jwt', certificateHash: 'hash' });

    const res = await fetch(`http://localhost:${port}/v1/sign-claims`, {
      method: 'POST',
      body: JSON.stringify({ sub: 'user-1' }),
    });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ certificate: 'jwt', certificateHash: 'hash' });
  });

  it('POST /v1/invalidate-signing-key-cache calls signer.invalidateSigningKeyCache', async () => {
    const res = await fetch(`http://localhost:${port}/v1/invalidate-signing-key-cache`, { method: 'POST' });

    expect(res.status).toBe(200);
    expect(mockSigner.invalidateSigningKeyCache).toHaveBeenCalled();
  });

  it('returns 400 with the error message when the signer throws (e.g. cascade not complete)', async () => {
    mockSigner.generateClaims.mockRejectedValue(new Error('Cannot generate certificate: key not shredded'));

    const res = await fetch(`http://localhost:${port}/v1/generate-claims`, { method: 'POST', body: '{}' });

    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: 'Cannot generate certificate: key not shredded' });
  });

  it('returns 404 for an unknown route', async () => {
    const res = await fetch(`http://localhost:${port}/v1/nonexistent`, { method: 'POST' });

    expect(res.status).toBe(404);
  });
});
