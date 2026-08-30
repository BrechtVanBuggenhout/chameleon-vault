import * as http from 'http';
import { CertificateSigner, GenerateClaimsInput } from './sign.js';
import { IdTokenVerifier, UnauthorizedError } from './auth.js';
import { createLogger } from './logger.js';
import { DestructionCertificateClaims } from '../types/index.js';

const logger = createLogger('certificate-signer-server');

export interface ServerConfig {
  idTokenAudience: string;
  allowedCallerEmail: string;
}

async function readJsonBody(req: http.IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(chunk as Buffer);
  }
  const raw = Buffer.concat(chunks).toString('utf8');
  return raw ? JSON.parse(raw) : {};
}

function sendJson(res: http.ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(payload);
}

/**
 * The network surface for CertificateSigner (chameleon-paper/
 * TEE_ATTESTATION_PLAN.md, Phase 2). Two separate endpoints for
 * generate/sign -- NOT one combined endpoint -- because
 * CertificateService.issueAndStoreCertificate calls generateClaims once but
 * may call signClaims more than once inside CertificateChainRepository
 * .appendToChain's Firestore transaction retry loop (see that method's own
 * docs); collapsing both into a single call would break that retry
 * semantics.
 *
 * Every route except /healthz requires a valid Google-signed ID token
 * identifying the expected caller (today: the key_vault Cloud Run
 * service's own service account) -- see auth.ts.
 */
export function createServer(signer: CertificateSigner, verifier: IdTokenVerifier, config: ServerConfig): http.Server {
  return http.createServer((req, res) => {
    void handleRequest(signer, verifier, config, req, res);
  });
}

async function handleRequest(
  signer: CertificateSigner,
  verifier: IdTokenVerifier,
  config: ServerConfig,
  req: http.IncomingMessage,
  res: http.ServerResponse
): Promise<void> {
  if (req.method === 'GET' && req.url === '/healthz') {
    sendJson(res, 200, { status: 'ok' });
    return;
  }

  try {
    await verifier.verify(req.headers.authorization, config.idTokenAudience, config.allowedCallerEmail);
  } catch (err) {
    if (err instanceof UnauthorizedError) {
      logger.warn({ reason: err.message, url: req.url }, 'Rejected unauthenticated request');
      sendJson(res, 401, { error: 'unauthorized' });
      return;
    }
    throw err;
  }

  try {
    if (req.method === 'POST' && req.url === '/v1/generate-claims') {
      const body = (await readJsonBody(req)) as GenerateClaimsInput;
      const claims = await signer.generateClaims(body);
      sendJson(res, 200, claims);
      return;
    }

    if (req.method === 'POST' && req.url === '/v1/sign-claims') {
      const body = (await readJsonBody(req)) as DestructionCertificateClaims;
      const result = await signer.signClaims(body);
      sendJson(res, 200, result);
      return;
    }

    if (req.method === 'POST' && req.url === '/v1/invalidate-signing-key-cache') {
      signer.invalidateSigningKeyCache();
      sendJson(res, 200, { status: 'ok' });
      return;
    }

    sendJson(res, 404, { error: 'not_found' });
  } catch (err) {
    logger.error({ err: (err as Error).message, url: req.url }, 'Request failed');
    sendJson(res, 400, { error: (err as Error).message });
  }
}
