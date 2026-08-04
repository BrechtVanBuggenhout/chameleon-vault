import { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { FirestoreRegistry } from '../gcp/firestore-registry.js';
import { CloudKMSClient } from '../gcp/cloud-kms.js';
import { decryptPiiVaultValue } from '../services/pii-vault-decryptor.js';
import { getRequestContext } from '../middleware/request-logging.js';
import type { ILineageRepository } from '../types/lineage.js';
import { createLogger } from '../logging/index.js';

const logger = createLogger('pii-vault-decrypt-route');

/** Narrow dependency: just the single-row ciphertext lookup, so tests don't need a real BigQuery client. */
export interface PiiVaultLookup {
  findCiphertext(params: {
    tenantId: string;
    userId: string;
    resourceId: string;
    fieldName: string;
  }): Promise<string | null>;
}

export interface PiiVaultDecryptRoutesOptions {
  piiVaultLookup: PiiVaultLookup;
  firestoreRegistry: FirestoreRegistry;
  dekKmsClient: CloudKMSClient;
  lineageRepository: ILineageRepository;
}

interface DecryptBody {
  userId?: string;
  resourceId?: string;
  fieldName?: string;
}

/**
 * On-demand, single-value decrypt for the console's "Decrypt" page --
 * distinct from /decrypted-views (a persistent BigQuery view declared once,
 * decrypted at query time by BigQuery itself) and from the demoted
 * /encrypt-/decrypt routes in crypto.ts (DeterministicAES, which only ever
 * matches Key Vault's own demo ciphertext, never real pii_vault data).
 * Reuses the exact real crypto path decrypted-views already proved out --
 * decryptPiiVaultValue (Firestore key lookup + KMS unwrap + ChameleonAesGcm)
 * -- against one looked-up row instead of a BigQuery remote-function batch.
 *
 * Auth: no special-casing -- the shared VAULT_API_KEY is sufficient here,
 * same trust model as every other console-facing route (Declare, Sync Now,
 * Deletion). Per-analyst attribution for this specific action was
 * considered and deliberately deferred for now; the mitigation is
 * operational (restrict who has console access), not technical.
 *
 * Never reveals *why* a value is unavailable -- an undeclared field, a
 * user with no synced row, and a shredded key all produce the same
 * `{ value: null }`, matching every other decrypt path in this API.
 */
export async function piiVaultDecryptRoutes(
  fastify: FastifyInstance,
  options: PiiVaultDecryptRoutesOptions
): Promise<void> {
  const { piiVaultLookup, firestoreRegistry, dekKmsClient, lineageRepository } = options;

  fastify.post(
    '/pii-vault/decrypt',
    { config: { rateLimit: { max: 30, timeWindow: '1 minute' } } },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const context = getRequestContext(request);
      context.operation = 'AD_HOC_DECRYPT';
      const tenantId = (request.headers['x-tenant-id'] as string) || 'default-tenant';
      const body = (request.body || {}) as DecryptBody;
      const { userId, resourceId, fieldName } = body;
      context.userId = userId;

      if (!userId || !resourceId || !fieldName) {
        return reply.status(400).send({
          statusCode: 400,
          error: 'userId, resourceId, and fieldName are all required',
        });
      }

      let rawCiphertext: string | null;
      try {
        rawCiphertext = await piiVaultLookup.findCiphertext({ tenantId, userId, resourceId, fieldName });
      } catch (error) {
        logger.error({ error, userId, resourceId, fieldName }, 'pii_vault lookup failed');
        return reply.status(500).send({ statusCode: 500, error: 'Lookup failed' });
      }

      // decryptPiiVaultValue never throws -- shredded keys and malformed
      // ciphertext are already handled internally and resolve to null.
      const value = await decryptPiiVaultValue(rawCiphertext, userId, tenantId, firestoreRegistry, dekKmsClient);

      try {
        await lineageRepository.recordEvent({
          userId,
          tenantId,
          source: 'key-vault',
          destination: 'pii-vault',
          eventType: 'AD_HOC_DECRYPT_PERFORMED',
          context: {
            operation: 'AD_HOC_DECRYPT',
            resourceId,
            fieldName,
            correlationId: context.correlationId,
            timestamp: new Date().toISOString(),
            analystEmail: context.analystEmail ?? null,
            found: value !== null,
          },
        });
      } catch (lineageError) {
        logger.error({ error: lineageError, userId, resourceId, fieldName }, 'Failed to record ad-hoc decrypt audit event');
      }

      logger.info(
        { correlationId: context.correlationId, userId, resourceId, fieldName, found: value !== null },
        'Ad-hoc decrypt request completed'
      );
      return reply.status(200).send({ value });
    }
  );
}
