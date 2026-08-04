import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { OAuth2Client } from 'google-auth-library';
import { FirestoreRegistry } from '../gcp/firestore-registry.js';
import { CloudKMSClient } from '../gcp/cloud-kms.js';
import { decryptPiiVaultValue } from '../services/pii-vault-decryptor.js';
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
  // The BigQuery connection's own auto-provisioned service account,
  // identified by its numeric unique ID (the JWT "sub"/"azp" claim) -- the
  // only identity this route will ever accept a call from. Required, not
  // optional: an unset value means "not configured," and this route must
  // fail closed, not silently skip verification.
  //
  // Deliberately NOT the SA's email. Confirmed live: a real, signature-
  // verified token from this connection carries no "email" claim at all
  // (just sub/azp/aud/iss/exp/iat) -- whatever mints BigQuery connection
  // tokens doesn't request the openid `email` scope. Comparing against
  // payload.email (the original implementation) meant this check could
  // never pass for a real caller.
  //
  // This value can't be derived automatically: it must be captured once,
  // manually, from a real request's verified JWT (surfaced by the logging
  // below on any mismatch) and wired in as config. Confirmed Google
  // exposes no API for it from a customer project -- iam.serviceAccounts.get
  // denies access to this class of shadow/service-agent SA even for the
  // project Owner, and BigQuery's own Connections API only ever returns
  // the SA's email, never its numeric ID. Only needs re-capturing if this
  // exact connection is ever destroyed and recreated (a new auto-
  // provisioned SA gets a new unique ID).
  allowedCallerUniqueId: string;
}

async function verifyCaller(
  authHeader: string | undefined,
  client: OAuth2Client,
  allowedCallerUniqueId: string,
  audience: string
): Promise<boolean> {
  if (!authHeader?.startsWith('Bearer ')) return false;
  const idToken = authHeader.slice('Bearer '.length);
  try {
    const ticket = await client.verifyIdToken({ idToken, audience });
    const payload = ticket.getPayload();
    const authorized = payload?.sub === allowedCallerUniqueId;
    if (!authorized) {
      // Token verified fine (right signature, right audience) but the
      // caller identity itself didn't clear the bar -- a materially
      // different failure than the catch block below, and one that
      // previously had zero logging of its own, making it indistinguishable
      // from "no token at all" in the logs.
      //
      // Logging the full verified payload -- its signature already passed
      // verifyIdToken above, so every claim on it is trustworthy, and this
      // is exactly how allowedCallerUniqueId's own real value gets
      // (re-)captured if this connection is ever recreated.
      logger.warn(
        { expectedCallerUniqueId: allowedCallerUniqueId, payload },
        'Decrypted-view caller ID token verified but identity did not match the allowed caller'
      );
    }
    return authorized;
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
  const { firestoreRegistry, dekKmsClient, allowedCallerUniqueId } = options;
  const authClient = new OAuth2Client();

  fastify.post('/internal/decrypted-views/batch-decrypt', async (request: FastifyRequest, reply: FastifyReply) => {
    if (!allowedCallerUniqueId) {
      logger.error('Decrypted-views batch-decrypt route is not configured -- refusing all requests');
      return reply.status(503).send({ statusCode: 503, error: 'Decrypted views not configured' });
    }

    const audience = `https://${request.hostname}${request.url}`;
    const authorized = await verifyCaller(
      request.headers['authorization'] as string | undefined,
      authClient,
      allowedCallerUniqueId,
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
          decryptPiiVaultValue(rawCiphertext, userId, tenantId, firestoreRegistry, dekKmsClient)
        )
      );
      return { replies };
    } catch (error) {
      logger.error({ error, requestId: body.requestId }, 'Batch decrypt failed');
      return reply.status(500).send({ errorMessage: 'Batch decrypt failed' });
    }
  });
}
