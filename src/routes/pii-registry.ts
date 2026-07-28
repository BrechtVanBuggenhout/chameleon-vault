import { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { createLogger } from '../logging/index.js';
import { PiiRegistryService, RegistryMutationError } from '../services/pii-registry-service.js';
import { buildManualEntry } from '../services/pii-registry-validation.js';
import { computeCoverage, toCoverageItems } from '../services/pii-coverage.js';
import { InvalidResourceIdError, type DiscoveredColumn } from '../gcp/bigquery-schema-service.js';
import type { PiiRegistryDeclarationInput } from '../types/pii-registry.js';
import type { WarehouseDiscoveryFinding } from '../types/lineage.js';

const logger = createLogger('pii-registry-routes');

const DEFAULT_TENANT = 'default-tenant';

/** Narrow dependency: just the discovery-findings reader from the lineage store. */
export interface DiscoveryFindingsSource {
  getWarehouseDiscoveryFindings?(tenantId?: string): Promise<WarehouseDiscoveryFinding[]>;
}

/** Narrow dependency: just the schema reader, so tests don't need a real BigQuery client. */
export interface SchemaSource {
  getColumns(resourceId: string): Promise<DiscoveredColumn[]>;
}

export interface PiiRegistryRoutesOptions {
  piiRegistryService: PiiRegistryService;
  /**
   * Shared secret required on write requests. When undefined, the declare API is
   * disabled (reads stay open) — writes mutate PII policy, so they are gated by default.
   */
  writeToken?: string;
  /** Source of crawler discovery findings for the "declare undeclared table" workflow. */
  discoverySource?: DiscoveryFindingsSource;
  /** Live BigQuery schema reader for the Declare form's column picker. Undefined disables it gracefully. */
  schemaSource?: SchemaSource;
}

function tenantOf(request: FastifyRequest): string {
  const header = request.headers['x-tenant-id'];
  const value = Array.isArray(header) ? header[0] : header;
  return value && value.trim() ? value.trim() : DEFAULT_TENANT;
}

export async function piiRegistryRoutes(
  fastify: FastifyInstance,
  options: PiiRegistryRoutesOptions
): Promise<void> {
  const { piiRegistryService, writeToken, discoverySource, schemaSource } = options;

  // Gate every mutating route behind the shared-secret bearer token.
  const requireWriteAuth = async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    if (!writeToken) {
      reply.status(503).send({ error: 'Registry write API is not enabled', statusCode: 503 });
      return;
    }
    const header = request.headers.authorization ?? '';
    const provided = header.startsWith('Bearer ') ? header.slice('Bearer '.length) : '';
    if (provided !== writeToken) {
      reply.status(401).send({ error: 'Unauthorized', statusCode: 401 });
      return;
    }
  };

  fastify.get('/pii-registry/resources', async (request, reply) => {
    try {
      const query = request.query as { system?: string; ownerConnector?: string; scanEnabled?: string };
      const scanEnabled = query.scanEnabled === undefined ? undefined : query.scanEnabled === 'true';
      const resources = piiRegistryService.listEntries({
        tenantId: tenantOf(request),
        system: query.system,
        ownerConnector: query.ownerConnector,
        scanEnabled,
      });

      return reply.send({
        resources,
        count: resources.length,
        timestamp: new Date().toISOString(),
      });
    } catch (error: unknown) {
      logger.error({ error }, 'Failed to list PII registry resources');
      return reply.status(500).send({
        error: 'Internal server error',
        statusCode: 500,
      });
    }
  });

  fastify.get('/pii-registry/resources/:resourceId', async (request, reply) => {
    const { resourceId } = request.params as { resourceId: string };
    const decodedResourceId = decodeURIComponent(resourceId);
    const resource = piiRegistryService.getEntry(decodedResourceId, tenantOf(request));

    if (!resource) {
      return reply.status(404).send({
        error: 'Resource not found in PII registry',
        statusCode: 404,
      });
    }

    return reply.send({
      resource,
      policy: piiRegistryService.evaluateEntry(resource),
      timestamp: new Date().toISOString(),
    });
  });

  fastify.get('/pii-registry/policy', async (request, reply) => {
    const evaluations = piiRegistryService.evaluateAll(tenantOf(request));
    const status = evaluations.some((evaluation) => evaluation.status === 'FAIL')
      ? 'FAIL'
      : evaluations.some((evaluation) => evaluation.status === 'WARN')
        ? 'WARN'
        : 'PASS';

    return reply.send({
      status,
      evaluations,
      timestamp: new Date().toISOString(),
    });
  });

  // Crypto-shred coverage score: % of the known PII surface that is fully shreddable,
  // composed from the registry, its policy evaluation, and undeclared crawler findings.
  fastify.get('/pii-registry/coverage', async (request, reply) => {
    const tenantId = tenantOf(request);
    try {
      const entries = piiRegistryService.listEntries({ tenantId });
      const discovery = discoverySource?.getWarehouseDiscoveryFindings
        ? await discoverySource.getWarehouseDiscoveryFindings(tenantId)
        : [];
      const items = toCoverageItems(entries, (entry) => piiRegistryService.evaluateEntry(entry).status, discovery);
      const report = computeCoverage(items);
      return reply.send({ ...report, timestamp: new Date().toISOString() });
    } catch (error) {
      logger.error({ error }, 'Failed to compute PII coverage');
      return reply.status(500).send({ error: 'Internal server error', statusCode: 500 });
    }
  });

  // Undeclared tables the warehouse crawler discovered — the "declare this" work queue.
  // Already-declared resources are filtered out so the list self-clears as users declare.
  fastify.get('/pii-registry/discovery', async (request, reply) => {
    const tenantId = tenantOf(request);
    if (!discoverySource?.getWarehouseDiscoveryFindings) {
      return reply.send({ findings: [], count: 0, timestamp: new Date().toISOString() });
    }
    try {
      const findings = await discoverySource.getWarehouseDiscoveryFindings(tenantId);
      const undeclared = findings.filter((finding) => !piiRegistryService.getEntry(finding.resourceId, tenantId));
      return reply.send({ findings: undeclared, count: undeclared.length, timestamp: new Date().toISOString() });
    } catch (error) {
      logger.error({ error }, 'Failed to list warehouse discovery findings');
      return reply.status(500).send({ error: 'Internal server error', statusCode: 500 });
    }
  });

  // Live column list for a resource ID, so the Declare form can offer real
  // columns to pick from instead of asking someone to type them from memory.
  // Read-only (INFORMATION_SCHEMA only, never table data) — no write auth needed.
  fastify.get('/pii-registry/schema', async (request, reply) => {
    const { resourceId } = request.query as { resourceId?: string };
    if (!resourceId) {
      return reply.status(400).send({ error: 'resourceId query parameter is required', statusCode: 400 });
    }
    if (!schemaSource) {
      return reply.status(503).send({ error: 'Schema introspection is not configured', statusCode: 503 });
    }
    try {
      const columns = await schemaSource.getColumns(resourceId);
      return reply.send({ resourceId, columns, count: columns.length, timestamp: new Date().toISOString() });
    } catch (error) {
      if (error instanceof InvalidResourceIdError) {
        return reply.status(400).send({ error: error.message, statusCode: 400 });
      }
      logger.error({ error, resourceId }, 'Failed to read BigQuery schema');
      return reply.status(502).send({
        error: 'Failed to read the table schema — check the resource ID and that Key Vault has access to it.',
        statusCode: 502,
      });
    }
  });

  // --- Write API: declare / update / remove a tenant-scoped PII resource ---

  const upsert = async (request: FastifyRequest, reply: FastifyReply, resourceIdFromPath?: string) => {
    const tenantId = tenantOf(request);
    const input = { ...(request.body as PiiRegistryDeclarationInput) };
    if (resourceIdFromPath) {
      input.resourceId = resourceIdFromPath;
    }

    const existing = input.resourceId ? piiRegistryService.getEntry(input.resourceId, tenantId) : undefined;
    // On PUT, only a tenant-owned manual entry may be edited.
    if (resourceIdFromPath && existing && existing.ownerConnector !== 'manual') {
      return reply.status(409).send({ error: 'This resource is platform-managed and cannot be edited', statusCode: 409 });
    }

    const { entry, errors } = buildManualEntry(input, tenantId, new Date(), existing);
    if (!entry) {
      return reply.status(400).send({ error: 'Invalid declaration', issues: errors, statusCode: 400 });
    }

    try {
      const saved = await piiRegistryService.upsertEntry(entry);
      const created = resourceIdFromPath ? false : !existing;
      return reply.status(created ? 201 : 200).send({
        resource: saved,
        policy: piiRegistryService.evaluateEntry(saved),
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      if (error instanceof RegistryMutationError) {
        return reply.status(409).send({ error: error.message, code: error.code, statusCode: 409 });
      }
      logger.error({ error }, 'Failed to persist PII declaration');
      return reply.status(500).send({ error: 'Failed to persist declaration', statusCode: 500 });
    }
  };

  fastify.post('/pii-registry/resources', { preHandler: requireWriteAuth }, async (request, reply) => {
    return upsert(request, reply);
  });

  fastify.put('/pii-registry/resources/:resourceId', { preHandler: requireWriteAuth }, async (request, reply) => {
    const { resourceId } = request.params as { resourceId: string };
    return upsert(request, reply, decodeURIComponent(resourceId));
  });

  fastify.delete('/pii-registry/resources/:resourceId', { preHandler: requireWriteAuth }, async (request, reply) => {
    const { resourceId } = request.params as { resourceId: string };
    const tenantId = tenantOf(request);
    try {
      const removed = await piiRegistryService.removeEntry(decodeURIComponent(resourceId), tenantId);
      if (!removed) {
        return reply.status(404).send({ error: 'No manual declaration found for this tenant', statusCode: 404 });
      }
      return reply.status(200).send({ removed: true, resourceId: decodeURIComponent(resourceId), timestamp: new Date().toISOString() });
    } catch (error) {
      if (error instanceof RegistryMutationError) {
        return reply.status(409).send({ error: error.message, code: error.code, statusCode: 409 });
      }
      logger.error({ error }, 'Failed to remove PII declaration');
      return reply.status(500).send({ error: 'Failed to remove declaration', statusCode: 500 });
    }
  });
}
