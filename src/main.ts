import Fastify from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import { getRequiredEnv } from './config/env.js';
import { createLogger } from './logging/index.js';
import { registerRequestLogging, getRequestContext } from './middleware/request-logging.js';
import { isExemptFromAuth, resolveAuth } from './middleware/auth.js';

// Import GCP Clients and Repositories
import { CloudKMSClient } from './gcp/cloud-kms.js';
import { FirestoreRegistry } from './gcp/firestore-registry.js';
import { BigQueryLineageRepository } from './gcp/bigquery-lineage.js';
import { DeletionRequestRepository } from './gcp/deletion-request-repository.js';
import { PubSubDLQClient } from './gcp/pubsub-dlq-client.js';
import { GCSClient } from './gcp/gcs-client.js';
import { AnalystAccessRepository } from './gcp/analyst-access-repository.js';

// Import Services
import { JanitorService } from './services/janitor.js';
import { DeletionRequestService } from './services/deletion-request-service.js';
import { CertificateService } from './services/certificate-service.js';
import { PiiRegistryService } from './services/pii-registry-service.js';
import { AnalystAccessService } from './services/analyst-access-service.js';
import { devPiiRegistry } from './data/pii-registry.js';
import { FirestorePiiDeclarationRepository } from './gcp/pii-registry-declaration-repository.js';
import { BigQueryPiiRegistryAuditMirror } from './gcp/pii-registry-audit-mirror.js';
import { BigQueryPiiRegistryRepository, composePiiRegistry } from './gcp/pii-registry-repository.js';
import { SnowflakePiiRegistryRepository } from './snowflake/pii-registry-repository.js';
import type { PiiRegistryEntry } from './types/pii-registry.js';

// Import Routes
import { healthRoutes } from './routes/health.js';
import { cryptoRoutes } from './routes/crypto.js';
import { lineageRoutes } from './routes/lineage.js';
import { deletionRequestRoutes } from './routes/deletion-requests.js';
import { certificateRoutes } from './routes/certificate.js';
import { piiRegistryRoutes } from './routes/pii-registry.js';
import { analystClaimsRoutes } from './routes/analyst-claims.js';

const logger = createLogger('main');

async function main() {
  const fastify = Fastify({
    logger: true, // Pino logger is configured in logging/index.ts
  });

  // Register global plugins
  await fastify.register(cors);
  await fastify.register(helmet);
  // global: false -- most routes are internal service-to-service traffic
  // (console, pipelines) already gated by VAULT_API_KEY below. Only the two
  // routes that can read/write plaintext on demand (/encrypt, /decrypt) opt
  // in via per-route `config.rateLimit` in crypto.ts, since those are the
  // ones a leaked API key could otherwise use to enumerate every user's data.
  await fastify.register(rateLimit, { global: false });
  await registerRequestLogging(fastify);

  // --- Dependency Injection Container Setup ---
  // 1. Environment Variables
  const projectId = getRequiredEnv('GCP_PROJECT_ID');
  const kmsRegion = getRequiredEnv('CLOUD_KMS_REGION');
  const kmsKeyRing = getRequiredEnv('CLOUD_KMS_KEY_RING');
  const kmsKeyName = getRequiredEnv('CLOUD_KMS_KEY_NAME');
  const signingKmsKeyRing = getRequiredEnv('CLOUD_KMS_SIGNING_KEY_RING');
  const signingKmsKeyName = getRequiredEnv('CLOUD_KMS_SIGNING_KEY_NAME');
  const firestoreCollection = getRequiredEnv('FIRESTORE_COLLECTION');
  const firestoreDeletionRequestCollection = getRequiredEnv('FIRESTORE_DELETION_REQUEST_COLLECTION');
  const firestoreDatabaseId = process.env.FIRESTORE_DATABASE_ID; // Optional
  const dlqTopic = process.env.JANITOR_DLQ_TOPIC_ID || `janitor-dead-letter-queue-${process.env.NODE_ENV === 'production' ? 'prod' : 'dev'}`;
  const auditBucket = getRequiredEnv('GCP_AUDIT_BUCKET_NAME');

  // 2. Initialize Low-Level Clients and Repositories (Singletons)
  const dekKmsClient = new CloudKMSClient(projectId, kmsRegion, kmsKeyRing, kmsKeyName);
  const signingKmsClient = new CloudKMSClient(projectId, kmsRegion, signingKmsKeyRing, signingKmsKeyName);
  const firestoreRegistry = new FirestoreRegistry(projectId, firestoreCollection, firestoreDatabaseId);
  const lineageRepository = new BigQueryLineageRepository(); // Assuming constructor doesn't need args or gets them from env
  const deletionRequestRepo = new DeletionRequestRepository(projectId, firestoreDeletionRequestCollection, firestoreDatabaseId);
  const pubSubDlqClient = new PubSubDLQClient(projectId, dlqTopic);
  const gcsClient = new GCSClient(projectId, auditBucket);

  // 3. Initialize Services (Inject Dependencies)
  const janitorService = new JanitorService(
    firestoreRegistry,
    lineageRepository,
    dekKmsClient, // DEK KMS client for encryption/decryption
    pubSubDlqClient
  );
  const certificateService = new CertificateService(firestoreRegistry, lineageRepository, signingKmsClient, gcsClient);

  // Federated PII registry, composed from three sources by owner:
  //  1. connector seed (devPiiRegistry) — bundled example/reference data for
  //     Chameleon's own deployments only. A fresh BYOC/managed deployment
  //     must not boot with Chameleon's own resource paths, so this is
  //     opt-in via PII_REGISTRY_USE_BUNDLED_SEED and empty by default.
  //  2. dbt slice — auto-registered from the chameleon_pii package's BigQuery tables
  //     (only when PII_REGISTRY_DATASET_ID is set),
  //  3. user-declared ("manual") slice — durable in Firestore, tenant-scoped.
  const connectorSeed: PiiRegistryEntry[] =
    process.env.PII_REGISTRY_USE_BUNDLED_SEED === 'true' ? devPiiRegistry : [];
  let dbtEntries: PiiRegistryEntry[] = [];

  const piiRegistryDataset = process.env.PII_REGISTRY_DATASET_ID;
  if (piiRegistryDataset) {
    try {
      const piiRegistryRepo = new BigQueryPiiRegistryRepository(projectId, piiRegistryDataset);
      const bqEntries = await piiRegistryRepo.loadEntries();
      dbtEntries = dbtEntries.concat(bqEntries);
      if (bqEntries.length > 0) {
        logger.info({ dbtCount: bqEntries.length }, 'Loaded dbt PII registry slice from BigQuery');
      } else {
        logger.warn('dbt PII registry tables returned no rows from BigQuery');
      }
    } catch (error) {
      logger.warn({ error }, 'Failed to load dbt PII registry from BigQuery');
    }
  } else {
    logger.info('PII_REGISTRY_DATASET_ID not set; BigQuery dbt registry slice disabled');
  }

  const snowflakeAccount = process.env.PII_REGISTRY_SNOWFLAKE_ACCOUNT;
  if (snowflakeAccount) {
    try {
      const piiRegistryRepo = new SnowflakePiiRegistryRepository({
        account: snowflakeAccount,
        username: getRequiredEnv('PII_REGISTRY_SNOWFLAKE_USER'),
        password: getRequiredEnv('PII_REGISTRY_SNOWFLAKE_PASSWORD'),
        role: process.env.PII_REGISTRY_SNOWFLAKE_ROLE,
        warehouse: getRequiredEnv('PII_REGISTRY_SNOWFLAKE_WAREHOUSE'),
        database: getRequiredEnv('PII_REGISTRY_SNOWFLAKE_DATABASE'),
        schema: getRequiredEnv('PII_REGISTRY_SNOWFLAKE_SCHEMA'),
      });
      const sfEntries = await piiRegistryRepo.loadEntries();
      dbtEntries = dbtEntries.concat(sfEntries);
      if (sfEntries.length > 0) {
        logger.info({ dbtCount: sfEntries.length }, 'Loaded dbt PII registry slice from Snowflake');
      } else {
        logger.warn('dbt PII registry tables returned no rows from Snowflake');
      }
    } catch (error) {
      logger.warn({ error }, 'Failed to load dbt PII registry from Snowflake');
    }
  } else {
    logger.info('PII_REGISTRY_SNOWFLAKE_ACCOUNT not set; Snowflake dbt registry slice disabled');
  }

  const declarationCollection = process.env.FIRESTORE_PII_DECLARATION_COLLECTION || 'pii_registry_declarations';
  const auditDatasetId = process.env.PII_AUDIT_DATASET_ID; // e.g. 'compliance'; empty disables the mirror
  const auditMirror = auditDatasetId
    ? new BigQueryPiiRegistryAuditMirror(projectId, auditDatasetId, process.env.PII_AUDIT_TABLE_ID || 'pii_metadata_registry')
    : undefined;
  const declarationRepo = new FirestorePiiDeclarationRepository(
    projectId,
    declarationCollection,
    firestoreDatabaseId,
    auditMirror
  );
  let manualEntries: PiiRegistryEntry[] = [];
  try {
    manualEntries = await declarationRepo.loadAll();
  } catch (error) {
    logger.warn({ error }, 'Failed to load manual PII declarations; continuing without them');
  }

  // Compose by owner: dbt slice replaces only dbt-owned connector entries; manual entries
  // (tenant-scoped, keyed by (tenant, resourceId)) layer on top without overwriting.
  const piiRegistryEntries = composePiiRegistry(connectorSeed, dbtEntries, manualEntries);
  const piiRegistryService = new PiiRegistryService(piiRegistryEntries, declarationRepo);
  const registryWriteToken = process.env.PII_REGISTRY_WRITE_TOKEN;
  if (!registryWriteToken) {
    logger.warn('PII_REGISTRY_WRITE_TOKEN not set; the declare API (POST/PUT/DELETE) is disabled.');
  }

  const deletionRequestService = new DeletionRequestService(
    deletionRequestRepo,
    firestoreRegistry,
    lineageRepository,
    janitorService,
    dekKmsClient, // DeletionRequestService also needs a KMS client for key destruction
    certificateService
  );

  const analystAccessCollection = process.env.FIRESTORE_ANALYST_ACCESS_COLLECTION || 'analyst_access';
  const analystAccessRepo = new AnalystAccessRepository(projectId, analystAccessCollection, firestoreDatabaseId);
  const analystAccessService = new AnalystAccessService(analystAccessRepo);

  // API key auth. Two tiers:
  //  1. The shared VAULT_API_KEY (unchanged) grants full access -- this is
  //     service-to-service traffic (console, pipelines).
  //  2. A per-analyst credential (issued via the one-time claim flow, see
  //     analyst-claims.ts) is accepted ONLY on /encrypt and /decrypt, so a
  //     leaked analyst key can't do anything a shared key could (rotate/
  //     shred keys, mint more analyst credentials, etc).
  // The claim-consumption route itself is exempt entirely, alongside
  // /health -- the analyst clicking that link has neither credential yet;
  // the one-time token in the URL is its own, separate authorization. See
  // middleware/auth.ts for the actual (independently tested) decision logic.
  const apiKey = process.env.VAULT_API_KEY;
  if (apiKey) {
    fastify.addHook('onRequest', async (request, reply) => {
      const path = request.url.split('?')[0];
      if (isExemptFromAuth(path)) return;

      const provided = request.headers['x-api-key'] ?? request.headers['authorization']?.replace('Bearer ', '');
      const result = await resolveAuth(path, provided as string | undefined, apiKey, analystAccessService);

      if (!result.authorized) {
        reply.code(401).send({ error: 'Unauthorized' });
        return;
      }
      if (result.analystEmail) {
        getRequestContext(request).analystEmail = result.analystEmail;
      }
    });
  } else {
    logger.warn('VAULT_API_KEY is not set — Key Vault is running without authentication');
  }

  // 4. Register Routes with Injected Dependencies
  await fastify.register(healthRoutes); // Health routes don't have external dependencies
  await fastify.register(cryptoRoutes, { kmsClient: dekKmsClient, firestoreRegistry, lineageRepository, deletionRequestService });
  await fastify.register(lineageRoutes, { lineageRepository, firestoreRegistry, janitorService });
  await fastify.register(deletionRequestRoutes, { deletionRequestService });
  await fastify.register(certificateRoutes, { certificateService });
  await fastify.register(piiRegistryRoutes, { piiRegistryService, writeToken: registryWriteToken, discoverySource: lineageRepository });
  await fastify.register(analystClaimsRoutes, { analystAccessService });

  const port = parseInt(process.env.PORT || '8080', 10);
  const address = '0.0.0.0';

  await fastify.listen({ port, host: address });
  logger.info(`Server listening on ${address}:${port}`);
}

main().catch((err) => {
  logger.error(err, 'Application failed to start');
  process.exit(1);
});
