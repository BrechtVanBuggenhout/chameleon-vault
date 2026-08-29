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
import { CertificateChainRepository } from './gcp/certificate-chain-repository.js';
import { DecryptedViewsRepository } from './gcp/decrypted-views-repository.js';
import { GithubActionsClient } from './gcp/github-actions-client.js';
import { TsaClient } from './gcp/tsa-client.js';
import { RekorClient } from './gcp/rekor-client.js';

// Import Services
import { JanitorService } from './services/janitor.js';
import { DeletionRequestService } from './services/deletion-request-service.js';
import { SourceRedactionService } from './services/source-redaction-service.js';
import { BigQuery } from '@google-cloud/bigquery';
import { CertificateService } from './services/certificate-service.js';
import { PiiRegistryService } from './services/pii-registry-service.js';
import { AnalystAccessService } from './services/analyst-access-service.js';
import { DecryptedViewService } from './services/decrypted-view-service.js';
import { devPiiRegistry } from './data/pii-registry.js';
import { FirestorePiiDeclarationRepository } from './gcp/pii-registry-declaration-repository.js';
import { SyncRunRepository } from './gcp/sync-run-repository.js';
import { BigQueryPiiRegistryAuditMirror } from './gcp/pii-registry-audit-mirror.js';
import { BigQueryPiiRegistryRepository, composePiiRegistry } from './gcp/pii-registry-repository.js';
import { BigQuerySchemaService } from './gcp/bigquery-schema-service.js';
import { PiiVaultSyncTrigger } from './gcp/pii-vault-sync-trigger.js';
import { SourceStalenessChecker } from './gcp/source-staleness-checker.js';
import { SnowflakePiiRegistryRepository } from './snowflake/pii-registry-repository.js';
import type { PiiRegistryEntry } from './types/pii-registry.js';

// Import Routes
import { healthRoutes } from './routes/health.js';
import { versionRoutes } from './routes/version.js';
import { cryptoRoutes } from './routes/crypto.js';
import { lineageRoutes } from './routes/lineage.js';
import { deletionRequestRoutes } from './routes/deletion-requests.js';
import { certificateRoutes } from './routes/certificate.js';
import { piiRegistryRoutes } from './routes/pii-registry.js';
import { syncRunsRoutes } from './routes/sync-runs.js';
import { analystClaimsRoutes } from './routes/analyst-claims.js';
import { auditorVerifyRoutes } from './routes/auditor-verify.js';
import { adminSessionCredentialsRoutes } from './routes/admin-session-credentials.js';
import { auditRoutes } from './routes/audit.js';
import { decryptedViewsRoutes } from './routes/decrypted-views.js';
import { decryptedViewsDecryptRoutes } from './routes/decrypted-views-decrypt.js';
import { piiVaultDecryptRoutes } from './routes/pii-vault-decrypt.js';
import { PiiVaultLookupService } from './services/pii-vault-lookup.js';

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
  const certificateChainCollection = process.env.FIRESTORE_CERTIFICATE_CHAIN_COLLECTION || 'certificate_chains';
  const certificateChainRepo = new CertificateChainRepository(projectId, certificateChainCollection, firestoreDatabaseId);

  // 3. Initialize Services (Inject Dependencies)
  const janitorService = new JanitorService(
    firestoreRegistry,
    lineageRepository,
    dekKmsClient, // DEK KMS client for encryption/decryption
    pubSubDlqClient
  );
  // RFC 3161 trusted timestamping: opt-in, off by default via the explicit
  // TSA_ENABLED switch (not just TSA_URL's presence) -- this is a brand-new,
  // always-in-the-critical-path dependency on a free, no-SLA third party
  // (issueAndStoreCertificate awaits it on the real POST
  // /deletion-requests/:id/advance path), so a fresh/BYOC deployment
  // shouldn't start calling it the moment this ships, and it needs to be
  // instantly killable (no deploy) if the TSA ever has an outage.
  const tsaClient = process.env.TSA_ENABLED === 'true'
    ? new TsaClient(process.env.TSA_URL || 'https://freetsa.org/tsr')
    : undefined;

  // Rekor transparency-log publishing: same opt-in shape as TSA above, same
  // reasoning. Uses a SEPARATE KMS key/client from signingKmsClient --
  // rekor.sigstore.dev's hashedrekord entry type rejects RSA-PSS signatures
  // (confirmed live, 2026-08-29), and certificate_signing_key's purpose
  // (RSA_SIGN_PSS_2048_SHA256) is fixed at creation, so it can never produce
  // a signature Rekor will accept. rekor_signing_key is EC_SIGN_P256_SHA256
  // instead, which Rekor does accept.
  const rekorClient = process.env.REKOR_ENABLED === 'true'
    ? (() => {
        const rekorKmsClient = new CloudKMSClient(
          projectId,
          kmsRegion,
          signingKmsKeyRing,
          getRequiredEnv('CLOUD_KMS_REKOR_SIGNING_KEY_NAME')
        );
        return new RekorClient(process.env.REKOR_URL || 'https://rekor.sigstore.dev', rekorKmsClient, () =>
          rekorKmsClient.getNewestEnabledVersion(rekorKmsClient.getCryptoKeyPath())
        );
      })()
    : undefined;

  const certificateService = new CertificateService(
    firestoreRegistry,
    lineageRepository,
    signingKmsClient,
    gcsClient,
    deletionRequestRepo,
    certificateChainRepo,
    tsaClient,
    rekorClient
  );

  // Optional: only self-hosted/Chameleon-managed deployments that also mirror
  // this service's source to a public repo (see sync-public-vault.yml) have
  // a public JWKS mirror to publish to. Unset means the feature simply
  // no-ops -- see certificate.ts's rotate handler.
  const githubActionsDispatchToken = process.env.GITHUB_ACTIONS_DISPATCH_TOKEN;
  const githubActionsClient = githubActionsDispatchToken
    ? new GithubActionsClient({
        token: githubActionsDispatchToken,
        owner: process.env.GITHUB_ACTIONS_REPO_OWNER || 'BrechtVanBuggenhout',
        repo: process.env.GITHUB_ACTIONS_REPO_NAME || 'chameleon-key-vault',
        workflowFile: 'publish-jwks-snapshot.yml',
      })
    : undefined;

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
  const schemaService = new BigQuerySchemaService(projectId);

  const syncRunCollection = process.env.FIRESTORE_SYNC_RUN_COLLECTION || 'sync_runs';
  const syncRunRepository = new SyncRunRepository(projectId, syncRunCollection, firestoreDatabaseId);

  const piiIngestorWorkerServiceName = process.env.PII_INGESTOR_WORKER_SERVICE_NAME;
  const piiIngestorWorkerRegion = process.env.PII_INGESTOR_WORKER_REGION;
  const syncTrigger =
    piiIngestorWorkerServiceName && piiIngestorWorkerRegion
      ? new PiiVaultSyncTrigger(projectId, piiIngestorWorkerRegion, piiIngestorWorkerServiceName)
      : undefined;
  if (!syncTrigger) {
    logger.info(
      'PII_INGESTOR_WORKER_SERVICE_NAME/_REGION not set; on-demand PII vault sync (/pii-registry/sync-now) is disabled'
    );
  }
  const sourceStalenessChecker =
    piiIngestorWorkerServiceName && piiIngestorWorkerRegion
      ? new SourceStalenessChecker(projectId, piiIngestorWorkerRegion, piiIngestorWorkerServiceName)
      : undefined;

  // PII_VAULT_RESOURCE_ID / DECRYPTED_VIEWS_BATCH_DECRYPT_FUNCTION_REF read
  // directly (not getRequiredEnv) -- optional here, unlike inside the
  // decrypted-views block above: REDACT_IN_PLACE (this service's other
  // strategy) never touches pii_vault at all, so a deployment can use it
  // with decrypted views disabled and these two unset entirely. Only
  // SHADOW_COPY needs them, and fails closed with a clear error if missing
  // rather than silently no-op-ing (see SourceRedactionService.ensureShadowCopy).
  const sourceRedactionService = new SourceRedactionService(
    piiRegistryService,
    new BigQuery({ projectId }),
    process.env.PII_VAULT_RESOURCE_ID,
    process.env.DECRYPTED_VIEWS_BATCH_DECRYPT_FUNCTION_REF
  );

  const deletionRequestService = new DeletionRequestService(
    deletionRequestRepo,
    firestoreRegistry,
    lineageRepository,
    janitorService,
    dekKmsClient, // DeletionRequestService also needs a KMS client for key destruction
    certificateService,
    sourceRedactionService
  );

  const analystAccessCollection = process.env.FIRESTORE_ANALYST_ACCESS_COLLECTION || 'analyst_access';
  const analystAccessRepo = new AnalystAccessRepository(projectId, analystAccessCollection, firestoreDatabaseId);
  const analystAccessService = new AnalystAccessService(analystAccessRepo);

  // Decrypted views: fully optional, opt-in subsystem (mirrors
  // enable_decrypted_views in chameleon-infra-gcp). DECRYPTED_VIEWS_DATASET
  // is the on/off switch -- when unset, neither route below is registered
  // at all (404, not a misconfigured 503), so an unconfigured deployment
  // has zero surface area for this feature, not a half-wired one.
  const decryptedViewsDataset = process.env.DECRYPTED_VIEWS_DATASET;
  let decryptedViewService: DecryptedViewService | undefined;
  let decryptedViewsRepo: DecryptedViewsRepository | undefined;
  if (decryptedViewsDataset) {
    const decryptedViewsCollection = process.env.FIRESTORE_DECRYPTED_VIEWS_COLLECTION || 'decrypted_views';
    decryptedViewsRepo = new DecryptedViewsRepository(projectId, decryptedViewsCollection, firestoreDatabaseId);
    decryptedViewService = new DecryptedViewService(
      projectId,
      decryptedViewsDataset,
      getRequiredEnv('DECRYPTED_VIEWS_BATCH_DECRYPT_FUNCTION_REF'),
      getRequiredEnv('PII_VAULT_RESOURCE_ID'),
      decryptedViewsRepo
    );
  } else {
    logger.info('DECRYPTED_VIEWS_DATASET not set; decrypted views are disabled');
  }

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
      if (result.role) {
        getRequestContext(request).credentialRole = result.role;
      }
    });
  } else {
    logger.warn('VAULT_API_KEY is not set — Key Vault is running without authentication');
  }

  // 4. Register Routes with Injected Dependencies
  await fastify.register(healthRoutes); // Health routes don't have external dependencies
  await fastify.register(versionRoutes, { sourceStalenessChecker });
  await fastify.register(cryptoRoutes, { kmsClient: dekKmsClient, firestoreRegistry, lineageRepository, deletionRequestService });
  await fastify.register(lineageRoutes, { lineageRepository, firestoreRegistry, janitorService });
  await fastify.register(deletionRequestRoutes, { deletionRequestService });
  await fastify.register(certificateRoutes, { certificateService, githubActionsClient });
  await fastify.register(piiRegistryRoutes, {
    piiRegistryService,
    writeToken: registryWriteToken,
    discoverySource: lineageRepository,
    schemaSource: schemaService,
    syncTrigger,
    sourceRedactionHook: sourceRedactionService,
  });
  await fastify.register(syncRunsRoutes, { syncRunRepository, writeToken: registryWriteToken });
  await fastify.register(analystClaimsRoutes, { analystAccessService });
  await fastify.register(adminSessionCredentialsRoutes, { analystAccessService });
  await fastify.register(auditorVerifyRoutes, { firestoreRegistry });
  await fastify.register(auditRoutes, { piiRegistryService, deletionRequestRepo });
  if (decryptedViewService && decryptedViewsRepo) {
    await fastify.register(decryptedViewsRoutes, {
      decryptedViewService,
      decryptedViewsRepository: decryptedViewsRepo,
    });
    await fastify.register(decryptedViewsDecryptRoutes, {
      firestoreRegistry,
      dekKmsClient,
      allowedCallerUniqueId: process.env.DECRYPTED_VIEWS_CONNECTION_SA_UNIQUE_ID || '',
    });
  }

  // Ad-hoc single-value decrypt (the console's "Decrypt" page). Independent
  // of decryptedViewsDataset above -- this route never touches the
  // BigQuery connection/remote-function machinery decrypted views needs, it
  // only needs to read pii_vault directly and decrypt server-side. Gated on
  // PII_VAULT_RESOURCE_ID alone so an unconfigured deployment has zero
  // surface area here, same "off by default" convention as decrypted views.
  if (process.env.PII_VAULT_RESOURCE_ID) {
    const piiVaultLookup = new PiiVaultLookupService(new BigQuery({ projectId }), process.env.PII_VAULT_RESOURCE_ID);
    await fastify.register(piiVaultDecryptRoutes, {
      piiVaultLookup,
      firestoreRegistry,
      dekKmsClient,
      lineageRepository,
    });
  } else {
    logger.info('PII_VAULT_RESOURCE_ID not set; ad-hoc decrypt is disabled');
  }

  const port = parseInt(process.env.PORT || '8080', 10);
  const address = '0.0.0.0';

  await fastify.listen({ port, host: address });
  logger.info(`Server listening on ${address}:${port}`);
}

main().catch((err) => {
  logger.error(err, 'Application failed to start');
  process.exit(1);
});
