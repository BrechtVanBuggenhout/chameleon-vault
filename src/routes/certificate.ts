import { FastifyInstance } from 'fastify';
import { CertificateService } from '../services/certificate-service.js';
import { createLogger } from '../logging/index.js';

const logger = createLogger('certificate-routes');

export async function certificateRoutes(
  fastify: FastifyInstance,
  options: { certificateService: CertificateService }
): Promise<void> {
  const { certificateService } = options;

  /**
   * GET /certificate/:userId
   * Returns the Certificate of Destruction (JWT) for a shredded user --
   * the exact one actually issued and chained, not a freshly re-signed
   * (and unchained) one. See CertificateService.getCertificateForUser.
   */
  fastify.get('/certificate/:userId', async (request, reply) => {
    const { userId } = request.params as { userId: string };
    const tenantId = (request.headers['x-tenant-id'] as string) || 'default-tenant';

    try {
      const { certificate } = await certificateService.getCertificateForUser(userId, tenantId);

      return {
        certificate,
        tenantId,
        userId,
        timestamp: new Date().toISOString()
      };
    } catch (error: unknown) {
      if (
        error instanceof Error &&
        (error.message.includes('not shredded') || error.message.includes('no completed deletion cascade'))
      ) {
        return reply.status(404).send({
          statusCode: 404,
          error: 'Certificate not available',
          message: error.message
        });
      }
      logger.error({ error, userId }, 'Failed to generate certificate');
      throw error;
    }
  });

  /**
   * GET /certificate-chain/by-hash/:hash
   * Returns the certificate whose own hash matches :hash -- lets a verifier
   * (see scripts/verify-cert.ts) walk previousCertificateHash backward
   * through a tenant's chain one link at a time. Unauthenticated by design:
   * see CertificateChainEntry / CertificateService.getCertificateByHash for
   * why a hash-keyed lookup can't be used to enumerate a tenant's history.
   */
  fastify.get('/certificate-chain/by-hash/:hash', async (request, reply) => {
    const { hash } = request.params as { hash: string };

    try {
      const result = await certificateService.getCertificateByHash(hash);
      if (!result) {
        return reply.status(404).send({
          statusCode: 404,
          error: 'Not found',
          message: `No certificate found with hash ${hash}`,
        });
      }
      return { ...result, timestamp: new Date().toISOString() };
    } catch (error) {
      logger.error({ error, hash }, 'Failed to look up certificate by hash');
      throw error;
    }
  });

  /**
   * GET /public-key
   * Returns the PEM-encoded public key used to verify certificates.
   */
  fastify.get('/public-key', async () => {
    try {
      const publicKey = await certificateService.getPublicKey();
      return {
        publicKey,
        algorithm: 'RSA_SIGN_PSS_2048_SHA256',
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      logger.error({ error }, 'Failed to fetch public key');
      throw error;
    }
  });

  /**
   * GET /.well-known/jwks.json
   * Returns the JSON Web Key Set for automatic certificate verification.
   */
  fastify.get('/.well-known/jwks.json', async () => {
    try {
      return await certificateService.getJwks();
    } catch (error) {
      logger.error({ error }, 'Failed to generate JWKS');
      throw error;
    }
  });

  /**
   * POST /admin/signing-key/rotate
   * Mints a new signing key version and promotes it to primary. Intended to
   * be called on a schedule (Cloud Scheduler), not by end users -- gated by
   * the same shared VAULT_API_KEY as every other non-exempt route.
   */
  fastify.post('/admin/signing-key/rotate', async (_request, reply) => {
    try {
      const result = await certificateService.rotateSigningKey();
      return {
        status: 'rotated',
        newVersion: result.newVersion,
        previousVersion: result.previousVersion,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      logger.error({ error }, 'Failed to rotate signing key');
      return reply.status(500).send({
        statusCode: 500,
        error: 'Rotation failed',
        message: error instanceof Error ? error.message : String(error),
      });
    }
  });
}
