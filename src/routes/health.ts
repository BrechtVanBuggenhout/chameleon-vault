import { FastifyInstance } from 'fastify';
import { createLogger } from '../logging/index.js';

const logger = createLogger('health-routes');

export interface HealthCheckDependency {
  ping(): Promise<void>;
}

export interface HealthRoutesOptions {
  firestore: HealthCheckDependency;
  kms: HealthCheckDependency;
}

// 3s cap so a slow/hanging dependency can't make Cloud Run's own health
// probe time out and repeatedly restart an otherwise-healthy instance --
// a check that can't complete quickly is itself a real signal to report
// as unhealthy, not something worth waiting longer for.
const CHECK_TIMEOUT_MS = 3_000;

async function withTimeout(promise: Promise<void>, label: string): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    await Promise.race([
      promise,
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error(`${label} check timed out after ${CHECK_TIMEOUT_MS}ms`)), CHECK_TIMEOUT_MS)),
    ]);
    return { ok: true };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : String(error) };
  }
}

export async function healthRoutes(fastify: FastifyInstance, options: HealthRoutesOptions): Promise<void> {
  const { firestore, kms } = options;

  // logLevel: 'silent' -- these are hit continuously by Cloud Run's own
  // health probes, not real traffic; without this every probe logs an
  // "incoming request"/"request completed" pair that drowns out real
  // request logs in prod.
  fastify.get('/health', { logLevel: 'silent' }, async (request, reply) => {
    const [firestoreResult, kmsResult] = await Promise.all([
      withTimeout(firestore.ping(), 'Firestore'),
      withTimeout(kms.ping(), 'KMS'),
    ]);

    const dependencies = { firestore: firestoreResult, kms: kmsResult };
    const healthy = firestoreResult.ok && kmsResult.ok;

    if (!healthy) {
      logger.error({ dependencies }, 'Health check failed');
    }

    return reply.status(healthy ? 200 : 503).send({
      status: healthy ? 'ok' : 'degraded',
      timestamp: new Date().toISOString(),
      service: 'chameleon-key-vault',
      version: '0.1.0',
      dependencies,
    });
  });
}
