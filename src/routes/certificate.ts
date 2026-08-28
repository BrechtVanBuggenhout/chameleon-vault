import { FastifyInstance } from 'fastify';
import { CertificateService } from '../services/certificate-service.js';
import { GithubActionsClient } from '../gcp/github-actions-client.js';
import { createLogger } from '../logging/index.js';

const logger = createLogger('certificate-routes');

export async function certificateRoutes(
  fastify: FastifyInstance,
  options: { certificateService: CertificateService; githubActionsClient?: GithubActionsClient }
): Promise<void> {
  const { certificateService, githubActionsClient } = options;

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
  fastify.post('/admin/signing-key/rotate', async (request, reply) => {
    try {
      const result = await certificateService.rotateSigningKey();

      // Awaited, not fire-and-forget -- confirmed live (2026-08-28) that an
      // un-awaited call here gets silently killed mid-flight: this service
      // runs with min_instance_count=0, and Cloud Run is free to scale an
      // instance down as soon as the triggering request's response is
      // sent, regardless of cpu_idle. Unawaited background work started
      // after that point isn't guaranteed to run to completion -- a real
      // rotation produced zero dispatch log output (neither success nor
      // the internal error paths) because the instance was reaped before
      // the GitHub API call finished. Still can't fail this route:
      // GithubActionsClient's own try/catch guarantees this never throws
      // and always resolves, so awaiting it only adds a bounded delay
      // (capped by its own 10s request timeout), never a failure mode.
      // baseUrl's hostname comes from the request itself, not a new env
      // var: this service can't reference its own Cloud Run .uri from
      // within its own Terraform resource block (a same-resource cycle),
      // and Cloud Scheduler's OIDC-authenticated call here carries the
      // real public hostname in its Host header. The scheme is hardcoded
      // to https, not derived from request.protocol -- confirmed live
      // (2026-08-28) that request.protocol reports "http" here, since
      // Cloud Run terminates TLS at its load balancer and forwards plain
      // HTTP to the container, and this app has no trustProxy configured
      // to read it back from X-Forwarded-Proto. A "http://...jwks.json"
      // URL made the poll below 302-redirect on every attempt (curl -sf
      // doesn't follow redirects), so it silently never found the new key
      // for the workflow's entire poll budget. Every Cloud Run service in
      // this org is HTTPS-only externally -- confirmed by that very
      // redirect -- so hardcoding is simpler and safer here than opting
      // this whole app into trustProxy just for one URL, which would also
      // change how the rate-limit plugin resolves client IPs elsewhere.
      if (githubActionsClient) {
        const baseUrl = `https://${request.hostname}`;
        await githubActionsClient.dispatchJwksSnapshot(result.newVersion, baseUrl);
      }

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
