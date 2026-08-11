import { FastifyInstance } from 'fastify';
import { SecretManagerServiceClient } from '@google-cloud/secret-manager';
import { SourceStalenessChecker } from '../gcp/source-staleness-checker.js';
import { createLogger } from '../logging/index.js';

const logger = createLogger('version');

// Matches the keys build-own-images.sh writes into the chameleon-source-shas
// secret -- see chameleon-infra-gcp/scripts/build-own-images.sh.
const SOURCE_SHAS_KEY = 'key-vault';

export async function versionRoutes(
  fastify: FastifyInstance,
  options: { sourceStalenessChecker?: SourceStalenessChecker } = {}
): Promise<void> {
  const { sourceStalenessChecker } = options;

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

  // GET /version/source-staleness -- proxies the PII Ingestor Worker's own
  // staleness check (compares this BYOC install's build-own-images.sh
  // source SHAs against the public repos' current HEAD). Proxied rather
  // than called directly by the console for the same reason Sync Now is:
  // the worker only grants roles/run.invoker to Pub/Sub and Key Vault, not
  // console, so this reuses that existing trust path instead of adding a
  // new one.
  fastify.get('/version/source-staleness', async (request, reply) => {
    if (!sourceStalenessChecker) {
      return reply.send({ status: 'not_applicable', reason: 'PII Ingestor Worker not configured' });
    }
    try {
      const result = await sourceStalenessChecker.check();
      return reply.send(result);
    } catch (error) {
      logger.error({ error }, 'Source staleness check failed');
      return reply.code(502).send({ status: 'error', reason: 'Failed to reach the PII Ingestor Worker' });
    }
  });
}
