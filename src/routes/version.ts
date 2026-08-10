import { FastifyInstance } from 'fastify';
import { SecretManagerServiceClient } from '@google-cloud/secret-manager';
import { createLogger } from '../logging/index.js';

const logger = createLogger('version');

// Matches the keys build-own-images.sh writes into the chameleon-source-shas
// secret -- see chameleon-infra-gcp/scripts/build-own-images.sh.
const SOURCE_SHAS_KEY = 'key-vault';

export async function versionRoutes(fastify: FastifyInstance): Promise<void> {
  fastify.get('/version', async (request, reply) => {
    const projectId = process.env.GCP_PROJECT_ID;
    let sources: Record<string, string> | null = null;

    if (projectId) {
      try {
        const client = new SecretManagerServiceClient();
        const [version] = await client.accessSecretVersion({
          name: `projects/${projectId}/secrets/chameleon-source-shas/versions/latest`,
        });
        const raw = Buffer.from(version.payload?.data ?? '').toString('utf8');
        sources = JSON.parse(raw) as Record<string, string>;
      } catch (error) {
        // chameleon-source-shas only exists for BYOC installs that ran
        // build-own-images.sh -- absence is expected (not an error) for
        // deployments pulling Chameleon's own pre-built images instead.
        logger.debug({ error }, 'chameleon-source-shas secret not available');
      }
    }

    return reply.send({
      service: 'chameleon-key-vault',
      sourceSha: sources?.[SOURCE_SHAS_KEY] ?? null,
      builtAt: sources?.builtAt ?? null,
      // Full map so callers that don't run GCP-facing code themselves (the
      // console) can proxy this one response instead of each needing their
      // own Secret Manager IAM grant -- see chameleon-console's /api/version.
      sources,
    });
  });
}
