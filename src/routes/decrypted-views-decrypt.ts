import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { OAuth2Client } from 'google-auth-library';
import { FirestoreRegistry } from '../gcp/firestore-registry.js';
import { CloudKMSClient } from '../gcp/cloud-kms.js';
import { ChameleonAesGcm } from '../crypto/chameleon-aes-gcm.js';
import { createLogger } from '../logging/index.js';

const logger = createLogger('decrypted-views-decrypt-route');

// BigQuery's remote-function request/response contract (documented shape,
// not something this app controls): one inner array per row, in the order
// declared on the view's CREATE FUNCTION DDL -- here always
// [encryptedValue, userId, tenantId].
interface RemoteFunctionRequest {
  requestId?: string;
  caller?: string;
  calls: [string | null, string | null, string | null][];
}

export interface DecryptedViewsDecryptRoutesOptions {
  firestoreRegistry: FirestoreRegistry;
  dekKmsClient: CloudKMSClient;
  // The BigQuery connection's own service account email -- the only
  // identity this route will ever accept a call from. Required, not
  // optional: an unset value means "not configured," and this route must
  // fail closed, not silently skip verification.
  allowedCallerServiceAccount: string;
}

async function verifyCaller(
  authHeader: string | undefined,
  client: OAuth2Client,
  allowedCallerServiceAccount: string,
  audience: string
): Promise<boolean> {
  if (!authHeader?.startsWith('Bearer ')) return false;
  const idToken = authHeader.slice('Bearer '.length);
  try {
    const ticket = await client.verifyIdToken({ idToken, audience });
    const payload = ticket.getPayload();
    return payload?.email === allowedCallerServiceAccount && payload?.email_verified !== false;
  } catch (error) {
    // Keyed "err", not "error" -- pino only applies its standard Error
    // serializer (message/stack/type) to that exact key. Logging the raw
    // Error under any other key silently prints "{}", since Error's own
    // properties are non-enumerable -- which is exactly what masked the
    // real cause of a real production 403 (audience/issuer mismatch vs.
    // wrong caller identity are very different bugs, and this line alone
    // couldn't tell them apart).
    //
    // decodeAudienceUnverified below reads the token's own "aud" claim
    // without checking its signature, purely so a future audience mismatch
    // (this exact bug, once already) is visible in one log line instead of
    // requiring a second round of guess-fix-redeploy-retry. The claim isn't
    // secret -- it's just the URL the caller intended to reach -- and it's
    // never trusted for anything; verifyIdToken above already ran and
    // failed by the time this executes.
    logger.warn(
      { err: error, requiredAudience: audience, actualAudience: decodeAudienceUnverified(idToken) },
      'Decrypted-view caller ID token failed verification'
    );
    return false;
  }
}

function decodeAudienceUnverified(idToken: string): string | undefined {
  try {
    const payloadSegment = idToken.split('.')[1];
    const payload = JSON.parse(Buffer.from(payloadSegment, 'base64url').toString('utf8'));
    return typeof payload?.aud === 'string' ? payload.aud : undefined;
  } catch {
    return undefined;
  }
}

/**
 * The endpoint a BigQuery Remote Function calls to perform live,
 * never-persisted decryption at query time -- the whole point of a
 * decrypted view. Deliberately NOT gated by the shared VAULT_API_KEY hook
 * (BigQuery has no way to present it); exempted in middleware/auth.ts and
 * self-authenticates here instead.
 *
 * Defense in depth, not a single point of failure: Cloud Run IAM invoker
 * (see chameleon-infra-gcp's decrypted_views.tf) is the first gate --
 * only the connection's service account can reach this route at all. This
 * handler verifies the caller's ID token itself as a second, independent
 * check, rather than trusting ingress alone -- load-bearing given
 * key_vault_allow_unauthenticated exists as a real, already-set flag on
 * Chameleon's own dev/prod.
 *
 * The expected audience is derived from the incoming request's own host
 * and path (`https://${request.hostname}${request.url}`), not a static
 * configured URL -- a Cloud Run service can't reference its own `.uri`
 * from within its own resource block in Terraform (a real dependency
 * cycle, not just an ordering inconvenience). The Host seen here is set by
 * Cloud Run's own front end, not client-supplied, the same trust boundary
 * Cloud Run's IAM check itself already relies on.
 *
 * Must include the path, not just the host: confirmed live (caught by
 * decodeAudienceUnverified's diagnostic logging below) that BigQuery mints
 * this token's "aud" claim as the exact endpoint URL configured on the
 * remote function -- host *and* path
 * (".../internal/decrypted-views/batch-decrypt") -- not just the service's
 * base URL the way e.g. a Cloud Scheduler oidc_token audience normally
 * would. Host-only here caused every real call to fail verification with
 * "Wrong recipient, payload audience != requiredAudience".
 *
 * A failed decrypt for one row (shredded key, malformed ciphertext) returns
 * null for that row rather than failing the whole batch or dropping the
 * row silently -- the same shape a shredded user already produces on
 * GET /decrypt today.
 */
export async function decryptedViewsDecryptRoutes(
  fastify: FastifyInstance,
  options: DecryptedViewsDecryptRoutesOptions
): Promise<void> {
  const { firestoreRegistry, dekKmsClient, allowedCallerServiceAccount } = options;
  const authClient = new OAuth2Client();

  fastify.post('/internal/decrypted-views/batch-decrypt', async (request: FastifyRequest, reply: FastifyReply) => {
    if (!allowedCallerServiceAccount) {
      logger.error('Decrypted-views batch-decrypt route is not configured -- refusing all requests');
      return reply.status(503).send({ statusCode: 503, error: 'Decrypted views not configured' });
    }

    const audience = `https://${request.hostname}${request.url}`;
    const authorized = await verifyCaller(
      request.headers['authorization'] as string | undefined,
      authClient,
      allowedCallerServiceAccount,
      audience
    );
    if (!authorized) {
      return reply.status(403).send({ statusCode: 403, error: 'Forbidden' });
    }

    const body = request.body as RemoteFunctionRequest;
    if (!Array.isArray(body?.calls)) {
      return reply.status(400).send({ errorMessage: 'Malformed request: missing calls array' });
    }

    try {
      const replies = await Promise.all(
        body.calls.map(([rawCiphertext, userId, tenantId]) =>
          decryptOne(rawCiphertext, userId, tenantId, firestoreRegistry, dekKmsClient)
        )
      );
      return { replies };
    } catch (error) {
      logger.error({ error, requestId: body.requestId }, 'Batch decrypt failed');
      return reply.status(500).send({ errorMessage: 'Batch decrypt failed' });
    }
  });
}

async function decryptOne(
  rawCiphertext: string | null,
  userId: string | null,
  tenantId: string | null,
  firestoreRegistry: FirestoreRegistry,
  dekKmsClient: CloudKMSClient
): Promise<string | null> {
  if (!rawCiphertext || !userId) return null;

  // pii_vault.encrypted_value's real on-disk format (chameleon-data-pipelines'
  // pii_vault_sync.py _encrypt_field): key_id:iv_b64:ciphertext_b64 -- three
  // parts, not two. Randomized AES-GCM (ChameleonAesGcm), not the
  // deterministic-IV scheme DeterministicAES uses; that class only ever
  // matches Key Vault's own demoted /encrypt-/decrypt routes, never
  // production ciphertext written by the pipeline.
  const parts = rawCiphertext.split(':');
  if (parts.length < 3) return null;
  const [keyVersionId, ivB64] = parts;
  const ciphertextB64 = parts.slice(2).join(':');
  if (!keyVersionId || !ivB64 || !ciphertextB64) return null;

  const keyData = await firestoreRegistry.getKeyForUser(userId, tenantId || 'default-tenant', keyVersionId);
  if (!keyData || !keyData.encryptedDek) return null;

  try {
    const dek = await dekKmsClient.decryptDataEncryptionKey(keyData.encryptedDek, tenantId || 'default-tenant');
    return ChameleonAesGcm.decrypt(ivB64, ciphertextB64, userId, dek);
  } catch (error) {
    logger.warn({ error, userId }, 'Failed to decrypt one row in a decrypted-view batch');
    return null;
  }
}
