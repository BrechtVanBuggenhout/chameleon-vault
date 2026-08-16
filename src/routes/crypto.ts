import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { DeterministicAES } from '../crypto/deterministic-aes.js';
import { FirestoreRegistry } from '../gcp/firestore-registry.js';
import { createLogger } from '../logging/index.js';
import { BigQueryLineageRepository } from '../gcp/bigquery-lineage.js';
import { CloudKMSClient } from '../gcp/cloud-kms.js';
import {
  encryptSchema,
  decryptSchema,
  keyGenerateSchema,
  keyRotateSchema,
  keyShredSchema,
  keyStatusSchema,
  batchGenerateSchema,
  batchEncryptionContextSchema, // Import new schema
  validateRequest,
  getEncryptionContextSchema,
} from '../middleware/validation.js';
import { getRequestContext } from '../middleware/request-logging.js';
import { DeletionRequestService } from '../services/deletion-request-service.js';

const logger = createLogger('crypto-routes');

export interface CryptoRoutesOptions {
  kmsClient: CloudKMSClient;
  firestoreRegistry: FirestoreRegistry;
  lineageRepository: BigQueryLineageRepository;
  deletionRequestService: DeletionRequestService;
}

export async function cryptoRoutes(
  fastify: FastifyInstance,
  { kmsClient, firestoreRegistry, lineageRepository, deletionRequestService }: CryptoRoutesOptions
): Promise<void> {
  // Helper to handle Firestore Timestamps or Date objects during serialization
  const formatTimestamp = (val: unknown): string | null => {
    if (!val) return null;
    if (typeof (val as { toISOString?: () => string }).toISOString === 'function') {
      return (val as { toISOString: () => string }).toISOString();
    }
    if (typeof (val as { toDate?: () => Date }).toDate === 'function') {
      return (val as { toDate: () => Date }).toDate().toISOString();
    }
    return String(val);
  };

  /**
   * POST /key/generate
   * Create a new encryption key for a user if one doesn't exist
   */
  fastify.post<{ Body: { userId?: string; user_id?: string } }>('/key/generate', async (request, reply) => {
    const context = getRequestContext(request);
    context.operation = 'KEY_GENERATE';

    // Phase 6: Multi-tenant tenantId extraction
    const tenantId = request.headers['x-tenant-id'] as string || 'default-tenant';
    if (!tenantId) {
      logger.warn({ correlationId: context.correlationId }, 'Request missing X-Tenant-Id header');
      // In Phase 6, we would return a 400 here. For now, we default to 'default-tenant'.
    }

    try {
      const body = await validateRequest(keyGenerateSchema, request.body) as any;
      const userId = body.userId || body.user_id;
      context.userId = userId;

      // Check if key already exists
      const existingKey = await firestoreRegistry.getKeyForUser(userId, tenantId);
      if (existingKey) {
        logger.info({ correlationId: context.correlationId, userId }, 'Key already exists, skipping generation');
        return reply.status(200).send({
          status: 'EXISTS',
          userId,
          user_id: userId,
          timestamp: new Date().toISOString(),
        });
      }

      // Phase 6: Ensure tenant-specific KMS key exists before generating user DEK
      await kmsClient.ensureTenantKey(tenantId);

      // Generate new random DEK encrypted by the tenant's KMS key
      const encryptedDek = await kmsClient.generateAndEncryptDek(tenantId);
      await firestoreRegistry.setKeyForUser(userId, encryptedDek, tenantId);

      try {
        await lineageRepository.recordEvent({
          userId,
          tenantId,
          source: 'key-vault',
          destination: 'key-registry',
          eventType: 'KEY_CREATED',
          dataClassification: 'AUDIT_TRAIL',
          context: {
            operation: 'KEY_GENERATE',
            correlationId: context.correlationId,
            key_id: 'v1',
            encryption_version: 'v2',
            timestamp: new Date().toISOString(),
          },
        });
      } catch (lineageError) {
        logger.error({ error: lineageError, userId }, 'Failed to record key generation audit event in lineage');
      }

      logger.info({ correlationId: context.correlationId, userId, severity: 'NOTICE' }, 'Key generated for user');
      const responseBody = {
        status: 'GENERATED',
        userId,
        user_id: userId,
        timestamp: new Date().toISOString(),
      };
      return reply.status(201).send(responseBody);
    } catch (error: unknown) {
      const err = error as { statusCode?: number; message?: string; errors?: unknown };
      if (err.statusCode === 400) {
        logger.warn(
          { correlationId: context.correlationId, userId: (request.body as any)?.userId || (request.body as any)?.user_id, error: err.message || 'Validation Error' },
          'Validation failed'
        );
        return reply.status(400).send({
          error: err.message || 'Validation Error',
          errors: err.errors,
          statusCode: 400,
        });
      }

      logger.error(
        { correlationId: context.correlationId, err: error, userId: (request.body as any)?.userId || (request.body as any)?.user_id },
        'Failed to generate key'
      );
      return reply.status(500).send({
        error: 'Failed to generate key',
        message: error instanceof Error ? error.message : String(error),
        statusCode: 500,
      });
    }
  });

  /**
   * POST /keys/batch-generate
   * POST /keys/batch-generate (Optimized for Ingestion Worker)
   * Optimization for Ingestion Worker: Generate keys for multiple users in one call.
   */
  fastify.post<{ Body: { tenantId?: string; tenant_id?: string; userIds: string[] } }>('/keys/batch-generate', async (request, reply) => {
    const context = getRequestContext(request);
    context.operation = 'BATCH_KEY_GENERATE';

    try {
      const body = await validateRequest(batchGenerateSchema, request.body) as { tenantId?: string; tenant_id?: string; userIds: string[] };
      const { userIds } = body;
      const tenantId = (request.headers['x-tenant-id'] as string) || body.tenantId || body.tenant_id || 'default-tenant';
      context.tenantId = tenantId;

      // Phase 6: Ensure tenant key exists once for the whole batch
      // Ensure tenant key exists once for the whole batch
      await kmsClient.ensureTenantKey(tenantId);

      // Process batch in parallel
      const results = await Promise.all(
        userIds.map(async (userId) => {
          const existingKey = await firestoreRegistry.getKeyForUser(userId, tenantId);
          if (existingKey) {
            return { userId, status: 'EXISTS' };
          }

          const encryptedDek = await kmsClient.generateAndEncryptDek(tenantId);
          await firestoreRegistry.setKeyForUser(userId, encryptedDek, tenantId);
          
          await lineageRepository.recordEvent({
            userId,
            tenantId,
            source: 'key-vault',
            destination: 'key-registry',
            eventType: 'KEY_CREATED',
            dataClassification: 'AUDIT_TRAIL',
            context: { operation: 'BATCH_GENERATE', correlationId: context.correlationId }
          }).catch(err => logger.error({ err, userId }, 'Lineage audit failed in batch'));

          return { userId, status: 'GENERATED' };
        })
      );

      return reply.status(200).send({
        processed: results.length,
        results,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      logger.error({ correlationId: context.correlationId, err: error }, 'Batch key generation failed');
      return reply.status(500).send({ error: 'Batch processing failed' });
    }
  });

  /**
   * POST /keys/batch-encryption-context
   * New endpoint for Ingestion Worker: Retrieve encryption contexts for multiple users in one call.
   */
  fastify.post<{ Body: { tenantId?: string; tenant_id?: string; userIds: string[] } }>('/keys/batch-encryption-context', async (request, reply) => {
    const context = getRequestContext(request);
    context.operation = 'BATCH_ENCRYPTION_CONTEXT';

    try {
      const body = await validateRequest(batchEncryptionContextSchema, request.body) as { tenantId?: string; tenant_id?: string; userIds: string[] };
      const { userIds } = body;
      const tenantId = (request.headers['x-tenant-id'] as string) || body.tenantId || body.tenant_id || 'default-tenant';
      context.tenantId = tenantId;

      // Ensure tenant key exists once for the whole batch
      await kmsClient.ensureTenantKey(tenantId);

      const results = await Promise.all(
        userIds.map(async (userId) => {
          try {
            const keyStatus = await firestoreRegistry.getKeyStatus(userId, tenantId);
            if (!keyStatus || keyStatus.status === 'SHREDDED' || keyStatus.status === 'DELETED') {
              logger.warn({ correlationId: context.correlationId, userId }, 'Key not found or shredded for encryption context in batch');
              return { userId, error: 'Key not found or shredded', statusCode: 404 };
            }

            const keyData = await firestoreRegistry.getKeyForUser(userId, tenantId);
            if (!keyData || !keyData.encryptedDek) {
              logger.error({ correlationId: context.correlationId, userId }, 'Encrypted DEK material missing for active key in batch');
              return { userId, error: 'Internal server error: Key material missing', statusCode: 500 };
            }

            const { encryptedDek, activeDekId } = keyData;

            return {
              userId,
              user_id: userId,
              keyId: activeDekId,
              key_id: activeDekId,
              encryptedDek: encryptedDek.toString('base64'),
              encrypted_dek: encryptedDek.toString('base64'),
              algorithm: 'AES-256-GCM',
              encryptionVersion: keyStatus.encryption_version || 'v1',
              encryption_version: keyStatus.encryption_version || 'v1',
              tokenization: {
                algorithm: 'HMAC-SHA256',
                tokenKeyId: 'chameleon-token-key-v1',
                token_key_id: 'chameleon-token-key-v1',
              },
              status: keyStatus.status,
              timestamp: new Date().toISOString(),
            };
          } catch (error) {
            logger.error({ correlationId: context.correlationId, userId, err: error }, 'Failed to get encryption context for user in batch');
            return { userId, error: 'Failed to retrieve encryption context', statusCode: 500 };
          }
        })
      );

      const contexts = results.filter((result): result is typeof result & { encryptedDek: string } => 'encryptedDek' in result);
      const contextsByUserId = Object.fromEntries(contexts.map((result) => [result.userId, result]));

      return reply.status(200).send({
        processed: results.length,
        contexts,
        contextsByUserId,
        contexts_by_user_id: contextsByUserId,
        results,
        timestamp: new Date().toISOString()
      });
    } catch (error: unknown) {
      const err = error as { statusCode?: number; message?: string; errors?: unknown };
      logger.error({ correlationId: context.correlationId, err: error }, 'Batch encryption context retrieval failed');
      return reply.status(err.statusCode || 500).send({
        error: err.message || 'Batch processing failed',
        errors: err.errors,
        statusCode: err.statusCode || 500,
      });
    }
  });

  /**
   * POST /encrypt (DEMOTED: For demo/testing only. Production should use /key/:userId/encryption-context
   * and perform local encryption in Repo 3 with randomized AES-GCM + HMAC tokenization.)
   *
   * Encrypt plaintext using user's DEK with deterministic AES-256-GCM.
   */
  fastify.post<{ Body: { plaintext: string; userId?: string; user_id?: string } }>(
    '/encrypt',
    // Rate-limited: a leaked VAULT_API_KEY (the credential hosted customers'
    // own analysts now hold, per the Phase 4 plan) could otherwise be used
    // to script arbitrary encrypt/decrypt calls with no throughput limit.
    { config: { rateLimit: { max: 30, timeWindow: '1 minute' } } },
    async (request, reply) => {
      const context = getRequestContext(request);
      context.operation = 'ENCRYPT';
      const tenantId = request.headers['x-tenant-id'] as string || 'default-tenant';

      try {
        const body = await validateRequest(encryptSchema, request.body) as any;
        const uId = body.userId || body.user_id;
        const { plaintext } = body;
        context.userId = uId;
        context.tenantId = tenantId;

        // Retrieve user's DEK
        const keyData = await firestoreRegistry.getKeyForUser(uId, tenantId);
        if (!keyData || !keyData.encryptedDek) {
          logger.warn({ correlationId: context.correlationId, userId: uId }, 'Key not found for encryption');
          return reply.status(404).send({
            error: 'User key not found. Generate key first using POST /key/generate',
            statusCode: 404,
          });
        }

        const { encryptedDek, activeDekId } = keyData;

        // Decrypt DEK using Cloud KMS
        const dek = await kmsClient.decryptDataEncryptionKey(encryptedDek, tenantId);

        // Encrypt with deterministic AES (NOTE: This is the old, risky deterministic GCM)
        const encryptedResult = DeterministicAES.encrypt(plaintext, uId, dek); // This should be randomized GCM in production
        const result = { ciphertext: `${activeDekId}:${encryptedResult.ciphertext}`, userId: uId, user_id: uId, timestamp: encryptedResult.timestamp };

        try {
          await lineageRepository.recordEvent({
            userId: uId,
            source: 'key-vault',
            tenantId,
            destination: 'encryption-audit',
          eventType: 'ENCRYPTION_PERFORMED',
            context: {
              operation: 'ENCRYPT',
              correlationId: context.correlationId,
              plaintextLength: plaintext.length,
              timestamp: new Date().toISOString(),
              // Set by main.ts's auth hook when the caller used a per-analyst
              // credential rather than the shared VAULT_API_KEY; null for
              // service-to-service callers.
              analystEmail: context.analystEmail ?? null,
            },
          });
        } catch (lineageError) {
          logger.error({ error: lineageError, userId: uId }, 'Failed to record encryption audit event in lineage');
        }

        logger.info(
          { correlationId: context.correlationId, userId: uId, plaintextLength: plaintext.length },
          'Successfully encrypted plaintext'
        );
        return reply.status(200).send(result);
      } catch (error: unknown) {
        const err = error as { statusCode?: number; message?: string; errors?: unknown };
        if (err.statusCode === 400) {
          logger.warn(
            { correlationId: context.correlationId, userId: (request.body as any)?.userId || (request.body as any)?.user_id, error: err.message || 'Validation Error' },
            'Validation failed'
          );
          return reply.status(400).send({
            error: err.message || 'Validation Error',
            errors: err.errors,
            statusCode: 400,
          });
        }

        logger.error(
          { correlationId: context.correlationId, err: error, userId: (request.body as any)?.userId || (request.body as any)?.user_id },
          'Failed to encrypt'
        );
        return reply.status(500).send({
          error: 'Failed to encrypt plaintext',
          message: error instanceof Error ? error.message : String(error),
          statusCode: 500,
        });
      }
    }
  );

  /**
   * POST /decrypt (DEMOTED: For demo/testing only. Production should use /key/:userId/encryption-context
   * and perform local decryption in Repo 3.)
   *
   * Decrypt ciphertext using user's DEK.
   */
  fastify.post<{ Body: { ciphertext: string; userId?: string; user_id?: string } }>(
    '/decrypt',
    { config: { rateLimit: { max: 30, timeWindow: '1 minute' } } },
    async (request, reply) => {
      const context = getRequestContext(request);
      context.operation = 'DECRYPT';
      const tenantId = request.headers['x-tenant-id'] as string || 'default-tenant';

      try {
        const body = await validateRequest(decryptSchema, request.body) as any;
        const uId = body.userId || body.user_id;
        const { ciphertext: rawCiphertext } = body;
        context.userId = uId;

        // Parse ciphertext to extract key version ID
        const [keyVersionId, actualCiphertext] = rawCiphertext.split(':', 2);
        if (!keyVersionId || !actualCiphertext) {
          throw new Error('Invalid ciphertext format');
        }
        // Retrieve user's DEK
        const keyData = await firestoreRegistry.getKeyForUser(uId, tenantId, keyVersionId);
        if (!keyData || !keyData.encryptedDek) {
          logger.warn({ correlationId: context.correlationId, userId: uId }, 'Key not found for decryption');
          return reply.status(404).send({
            error: 'User key not found or has been shredded',
            statusCode: 404,
          });
        }

        const { encryptedDek } = keyData;

        // Decrypt DEK using Cloud KMS
        const dek = await kmsClient.decryptDataEncryptionKey(encryptedDek, tenantId);

        // Decrypt with deterministic AES
        const decryptResult = DeterministicAES.decrypt(actualCiphertext, uId, dek);
        const result = {
          plaintext: decryptResult.plaintext,
          userId: decryptResult.userId,
          user_id: decryptResult.userId,
          timestamp: decryptResult.timestamp
        };

        // Unlike /encrypt, this previously recorded no lineage event at all --
        // a real gap, since reading plaintext back out is the more sensitive
        // of the two operations. Non-blocking, same as /encrypt's own event.
        try {
          await lineageRepository.recordEvent({
            userId: uId,
            tenantId,
            source: 'key-vault',
            destination: 'decryption-audit',
            eventType: 'DECRYPTION_PERFORMED',
            context: {
              operation: 'DECRYPT',
              correlationId: context.correlationId,
              timestamp: new Date().toISOString(),
              analystEmail: context.analystEmail ?? null,
            },
          });
        } catch (lineageError) {
          logger.error({ error: lineageError, userId: uId }, 'Failed to record decryption audit event in lineage');
        }

        logger.info(
          { correlationId: context.correlationId, userId: uId, severity: 'NOTICE' },
          'Successfully decrypted ciphertext'
        );
        return reply.status(200).send(result);
      } catch (error: unknown) {
        const err = error as { statusCode?: number; message?: string; errors?: unknown };
        if (err.statusCode === 400) {
          logger.warn(
            { correlationId: context.correlationId, userId: (request.body as any)?.userId || (request.body as any)?.user_id, error: err.message || 'Validation Error' },
            'Validation failed'
          );
          return reply.status(400).send({
            error: err.message || 'Validation Error',
            errors: err.errors,
            statusCode: 400,
          });
        }

        // GCM authentication failed (tampered ciphertext) or decryption error
        logger.warn(
          { correlationId: context.correlationId, error: err.message, userId: (request.body as any)?.userId || (request.body as any)?.user_id },
          'Failed to decrypt (invalid ciphertext or tampering detected)'
        );
        return reply.status(400).send({
          error: 'Failed to decrypt. Ciphertext may be invalid or tampered.',
          statusCode: 400,
        });
      }
    }
  );

  /**
   * GET /key-status/:userId
   * Query the lifecycle status of a user's encryption key
   */
  fastify.get<{ Params: { userId: string } }>('/key-status/:userId', async (request, reply) => {
    const context = getRequestContext(request);
    context.operation = 'KEY_STATUS';
    const tenantId = request.headers['x-tenant-id'] as string || 'default-tenant';

    try {
      const { userId } = await validateRequest(keyStatusSchema, request.params);
      context.userId = userId;

      const status = await firestoreRegistry.getKeyStatus(userId, tenantId);
      if (!status) {
        logger.info({ correlationId: context.correlationId, userId }, 'Key status not found');
        return reply.status(404).send({
          error: 'Key not found for user',
          statusCode: 404,
        });
      }

      logger.info(
        { correlationId: context.correlationId, userId, status: status.status },
        'Retrieved key status'
      );
      return reply.status(200).send({
        userId,
        user_id: userId,
        status: status.status || 'UNKNOWN',
        createdAt: formatTimestamp(status.created_at),
        created_at: formatTimestamp(status.created_at),
        shredAt: formatTimestamp(status.shred_at),
        shred_at: formatTimestamp(status.shred_at),
        rotatedAt: formatTimestamp(status.rotated_at),
        rotated_at: formatTimestamp(status.rotated_at),
        activeDekId: status.active_dek_id || null,
        active_dek_id: status.active_dek_id || null,
        encryptionVersion: status.encryption_version || 'v1',
        encryption_version: status.encryption_version || 'v1',
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error(
        { correlationId: context.correlationId, error, userId: request.params.userId },
        'Failed to get key status'
      );
      return reply.status(500).send({
        error: 'Failed to retrieve key status',
        message: error instanceof Error ? error.message : String(error),
        statusCode: 500,
      });
    }
  });

  /**
   * DELETE /key/shred (DEMOTED: This endpoint now initiates a deletion request,
   * which then orchestrates the actual key destruction and Janitor cascade.)
   *
   * Initiates the deletion process for a user's encryption key.
   */
  fastify.delete<{ Body: { userId?: string; user_id?: string; operationId?: string; operation_id?: string } }>('/key/shred', async (request, reply) => {
    const context = getRequestContext(request);
    context.operation = 'KEY_SHRED';
    const tenantId = request.headers['x-tenant-id'] as string || 'default-tenant';

    try {
      const body = await validateRequest(keyShredSchema, request.body) as any;
      const userId = body.userId || body.user_id;
      context.userId = userId;

      // Use a unique operation ID for idempotency
      const operationId = body.operationId || body.operation_id || context.correlationId || `shred-${userId}-${Date.now()}`; // Allow client to provide operationId

      // Check for existing active deletion request
      const existingDeletionRequest = await deletionRequestService.getRequest(operationId); // Check by operationId for idempotency
      
      if (existingDeletionRequest) {
        logger.info({ correlationId: context.correlationId, userId, operationId }, 'Deletion request already exists, returning status');
        // If a deletion request already exists, return its current status.
        // This handles cases where the key might have been shredded in a previous attempt.
        // The API_SPECIFICATION.md states "200 OK – Key successfully shredded (or already shredded)"
        // So, if a request exists, we return 200 with its status.
        // If the key was already deleted, the existingDeletionRequest would reflect that.
        // If the key was not found in the registry, but a deletion request exists, it means the process was initiated.
        // We should return the status of the existing deletion request.
        // The only case where we should return 404 is if no key exists AND no deletion request exists.
        return reply.status(200).send({
          status: existingDeletionRequest.status,
          userId,
          user_id: userId,
          deletionRequestId: existingDeletionRequest.deletion_request_id,
          deletion_request_id: existingDeletionRequest.deletion_request_id,
          timestamp: new Date().toISOString(),
          message: 'Deletion process is already in progress or completed.',
        });
      }
      
      // If no existing deletion request, check if the key exists in the registry.
      const keyEntry = await firestoreRegistry.getKeyStatus(userId, tenantId);
      if (!keyEntry) {
        return reply.status(404).send({
          error: 'User key not found',
          statusCode: 404,
        });
      }

      if (keyEntry.status === 'SHREDDED') {
        logger.info({ userId }, 'Key already shredded, returning idempotent success');
        return reply.status(200).send({
          status: 'CERTIFICATE_ISSUED',
          userId,
          user_id: userId,
          timestamp: new Date().toISOString(),
          message: 'Key successfully shredded (already shredded and certificate issued)',
        });
      }

      // Initiate the deletion request state machine
      const created = await deletionRequestService.createRequest(userId, operationId, tenantId);
      let deletionRequest = created.request;

      if (created.alreadyExisted) {
        // A request for this user is already past SHRED_REQUESTED (possibly
        // stuck in CASCADE_PARTIAL_FAILURE) -- advancing straight to
        // KEY_DESTROYED here would hit an invalid state transition, exactly
        // the bug this route shared with POST /deletion-requests. Report its
        // real current status instead of blindly advancing it; retrying a
        // stuck cascade goes through POST /deletion-requests/:id/advance
        // with newStatus=CASCADE_IN_PROGRESS.
        logger.info(
          { correlationId: context.correlationId, userId, deletionRequestId: deletionRequest.deletion_request_id, status: deletionRequest.status },
          'Deletion request already exists for user, returning its current status instead of re-advancing'
        );
        return reply.status(200).send({
          status: deletionRequest.status,
          userId,
          user_id: userId,
          deletionRequestId: deletionRequest.deletion_request_id,
          deletion_request_id: deletionRequest.deletion_request_id,
          timestamp: new Date().toISOString(),
          message: 'Deletion process is already in progress or completed.',
        });
      }

      // Immediately advance to KEY_DESTROYED (this will trigger actual DEK removal)
      deletionRequest = await deletionRequestService.advanceRequest(deletionRequest.deletion_request_id, 'KEY_DESTROYED', operationId);

      // Then advance to CASCADE_PENDING (this will trigger Janitor dispatch)
      deletionRequest = await deletionRequestService.advanceRequest(deletionRequest.deletion_request_id, 'CASCADE_PENDING', operationId);

      // The response reflects the initiation of the process, not necessarily its completion
      logger.info(
        {
          correlationId: context.correlationId,
          userId,
          deletion_request_id: deletionRequest.deletion_request_id,
          severity: 'NOTICE',
          event: 'KEY_DESTRUCTION',
        },
        'Deletion process initiated for user (mathematical erasure and cascade triggered)'
      );
      return reply.status(200).send({
        status: deletionRequest.status, // Should be SHRED_REQUESTED initially
        userId,
        user_id: userId,
        deletionRequestId: deletionRequest.deletion_request_id,
        deletion_request_id: deletionRequest.deletion_request_id,
        timestamp: new Date().toISOString(),
        message: 'Key destroyed. All encrypted data is now mathematically unrecoverable.',
      });
    } catch (error: unknown) {
      const err = error as { statusCode?: number; message?: string; errors?: unknown };
      if (err.statusCode === 400) {
        logger.warn(
          { correlationId: context.correlationId, userId: (request.body as any)?.userId || (request.body as any)?.user_id, error: err.message || 'Validation Error' },
          'Validation failed'
        );
        return reply.status(400).send({
          error: err.message || 'Validation Error',
          errors: err.errors,
          statusCode: 400,
        });
      }

      logger.error(
        { correlationId: context.correlationId, err: error, userId: (request.body as any)?.userId || (request.body as any)?.user_id },
        'Failed to shred key'
      );
      return reply.status(500).send({
        error: 'Failed to shred key',
          message: error instanceof Error ? error.message : String(error),
        statusCode: 500,
      });
    }
  });

  // Shared handler for encryption context to support both singular and plural aliases
  const getEncryptionContextHandler = async (request: FastifyRequest<{ Params: { userId: string } }>, reply: FastifyReply): Promise<void> => {
    const context = getRequestContext(request);
    context.operation = 'GET_ENCRYPTION_CONTEXT';
    const tenantId = request.headers['x-tenant-id'] as string || 'default-tenant';

    try {
      const body = await validateRequest(getEncryptionContextSchema, request.params);
      const uId = body.userId || body.user_id;
      context.userId = uId;

      const keyStatus = await firestoreRegistry.getKeyStatus(uId, tenantId);
      if (!keyStatus || keyStatus.status === 'SHREDDED' || keyStatus.status === 'DELETED') {
        logger.warn({ correlationId: context.correlationId, userId: uId }, 'Key not found or shredded for encryption context');
        return reply.status(404).send({
          error: 'User key not found or has been shredded',
          statusCode: 404,
        });
      }

      // Retrieve the encrypted DEK (Repo 3 will decrypt it locally)
      const keyData = await firestoreRegistry.getKeyForUser(uId, tenantId);
      if (!keyData || !keyData.encryptedDek) {
        logger.error({ correlationId: context.correlationId, userId: uId }, 'Encrypted DEK material missing for active key');
        return reply.status(500).send({
          error: 'Internal server error: Key material missing',
          statusCode: 500,
        });
      }

      const { encryptedDek, activeDekId } = keyData;

      // Construct the encryption context for Repo 3
      const encryptionContext = {
        operationId: context.correlationId,
        operation_id: context.correlationId,
        userId: uId,
        user_id: uId,
        keyId: activeDekId,
        key_id: activeDekId,
        encryptedDek: encryptedDek.toString('base64'),
        encrypted_dek: encryptedDek.toString('base64'),
        algorithm: 'AES-256-GCM', // Randomized GCM
        encryptionVersion: keyStatus.encryption_version || 'v1',
        encryption_version: keyStatus.encryption_version || 'v1',
        tokenization: {
          algorithm: 'HMAC-SHA256',
          tokenKeyId: 'chameleon-token-key-v1',
          token_key_id: 'chameleon-token-key-v1',
        },
        status: keyStatus.status,
        timestamp: new Date().toISOString(),
      };

      logger.info({ correlationId: context.correlationId, userId: uId }, 'Provided encryption context');
      return reply.status(200).send(encryptionContext);
    } catch (error: unknown) {
      return reply.status(500).send({
        error: 'Failed to retrieve encryption context',
        message: error instanceof Error ? error.message : String(error),
        statusCode: 500,
      });
    }
  };

  /**
   * GET /key/:userId/encryption-context
   * Provides the necessary metadata for Repo 3 to perform local encryption and tokenization.
   */
  fastify.get<{ Params: { userId: string } }>('/key/:userId/encryption-context', getEncryptionContextHandler);

  /**
   * Alias for the pluralized endpoint used by some data plane clients and stress tests
   */
  fastify.get<{ Params: { userId: string } }>('/keys/:userId/encryption-context', getEncryptionContextHandler);

  /**
   * POST /key/rotate
   * Generates a new Data Encryption Key (DEK) for the user and sets it as active.
   */
  fastify.post<{ Body: { userId?: string; user_id?: string } }>('/key/rotate', async (request, reply) => {
    const context = getRequestContext(request);
    context.operation = 'KEY_ROTATE';

    try {
      const body = await validateRequest(keyRotateSchema, request.body) as any;
      const userId = body.userId || body.user_id;
      context.userId = userId;
      const tenantId = request.headers['x-tenant-id'] as string || 'default-tenant';

      // Ensure tenant key exists (idempotent)
      await kmsClient.ensureTenantKey(tenantId);

      // Generate a new DEK and encrypt it with the tenant's KMS key
      const newEncryptedDek = await kmsClient.generateAndEncryptDek(tenantId);

      // Rotate the key in the registry
      const newVersionId = await firestoreRegistry.rotateKeyForUser(userId, newEncryptedDek, tenantId);

      try {
        await lineageRepository.recordEvent({
          userId,
          source: 'key-vault',
          destination: 'key-rotation-audit',
          eventType: 'KEY_ROTATED',
          context: {
            operation: 'KEY_ROTATE',
            correlationId: context.correlationId,
            newVersionId,
            timestamp: new Date().toISOString(),
          },
        });
      } catch (lineageError) {
        logger.error({ error: lineageError, userId }, 'Failed to record key rotation audit event in lineage');
      }

      logger.info({ correlationId: context.correlationId, userId, newVersionId, severity: 'NOTICE' }, 'Key rotated for user');
      return reply.status(200).send({
        status: 'ROTATED',
        userId,
        user_id: userId,
        timestamp: new Date().toISOString(),
      });
    } catch (error: unknown) {
      const err = error as { message?: string };
      if (err.message === 'User key not found for rotation' || err.message === 'Cannot rotate a shredded key') {
        logger.warn({ correlationId: context.correlationId, userId: (request.body as any)?.userId || (request.body as any)?.user_id, error: err.message || 'Rotation Error' }, 'Key rotation failed due to key status');
        return reply.status(404).send({
          error: 'User key not found or shredded',
          statusCode: 404,
        });
      }
      logger.error({ correlationId: context.correlationId, error, userId: (request.body as any)?.userId || (request.body as any)?.user_id }, 'Failed to rotate key');
      return reply.status(500).send({
        error: 'Failed to rotate key',
        statusCode: 500,
      });
    }
  });
}
