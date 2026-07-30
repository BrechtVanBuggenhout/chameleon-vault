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
   * Returns a signed Certificate of Destruction (JWT) for a shredded user.
   */
  fastify.get('/certificate/:userId', async (request, reply) => {
    const { userId } = request.params as { userId: string };
    const tenantId = (request.headers['x-tenant-id'] as string) || 'default-tenant';

    try {
      const claims = await certificateService.generateCertificateClaims(userId, tenantId);
      const certificate = await certificateService.signCertificate(claims);

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
}
