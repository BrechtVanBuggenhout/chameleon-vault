import { describe, expect, it, jest } from '@jest/globals';
import Fastify from 'fastify';
import { PiiRegistryService } from '../src/services/pii-registry-service.js';
import { auditRoutes } from '../src/routes/audit.js';
import type { DeletionRequestRepository } from '../src/gcp/deletion-request-repository.js';
import type { PiiRegistryEntry } from '../src/types/pii-registry.js';
import type { DeletionRequest } from '../src/types/deletion-request.js';

const declaredEntry: PiiRegistryEntry = {
  registryVersion: '2026-08-10',
  resourceId: 'bigquery:acme.raw.contacts',
  system: 'bigquery',
  piiFields: [],
  ownerConnector: 'manual',
  lineageDestination: 'bigquery:acme.raw.contacts',
  deletionStrategy: 'CRYPTO_SHRED',
  ghostDataScan: { enabled: true, scanMode: 'SAMPLED', patterns: [] },
  handlingPolicy: 'manual_declaration',
  evidencePointers: [],
  tenantId: 'acme',
  createdAt: '2026-08-01T00:00:00.000Z',
  updatedAt: '2026-08-05T00:00:00.000Z',
  declaredBy: 'analyst@example.com',
  lastModifiedBy: 'someone-else@example.com',
};

function makeFakeDeletionRequestRepo(requests: DeletionRequest[]) {
  return {
    listByRequestedBy: jest.fn(async () => requests),
  } as unknown as DeletionRequestRepository;
}

describe('auditRoutes', () => {
  it('GET /audit/actor/:email combines registry declare/modify events and deletion requests, newest first', async () => {
    const piiRegistryService = new PiiRegistryService([declaredEntry]);
    const deletionRequestRepo = makeFakeDeletionRequestRepo([
      {
        deletion_request_id: 'delreq-1',
        tenant_id: 'acme',
        user_id: 'user-42',
        status: 'SHRED_REQUESTED',
        created_at: new Date('2026-08-08T00:00:00.000Z'),
        status_history: [],
        janitor_wipes: [],
        requested_by: 'analyst@example.com',
      },
    ]);

    const app = Fastify({ logger: false });
    await app.register(auditRoutes, { piiRegistryService, deletionRequestRepo });

    const res = await app.inject({ method: 'GET', url: '/audit/actor/analyst%40example.com', headers: { 'x-tenant-id': 'acme' } });
    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.body);

    expect(body.actorEmail).toBe('analyst@example.com');
    expect(body.count).toBe(2);
    // Newest first: the deletion request (Aug 8) before the declare event (Aug 1).
    expect(body.events[0].type).toBe('DELETION_REQUESTED');
    expect(body.events[0].resourceId).toBe('user-42');
    expect(body.events[1].type).toBe('PII_REGISTRY_DECLARED');
    expect(body.events[1].resourceId).toBe('bigquery:acme.raw.contacts');

    await app.close();
  });

  it('does not surface a MODIFIED event for a different actor even though DECLARED matches', async () => {
    const piiRegistryService = new PiiRegistryService([declaredEntry]);
    const deletionRequestRepo = makeFakeDeletionRequestRepo([]);

    const app = Fastify({ logger: false });
    await app.register(auditRoutes, { piiRegistryService, deletionRequestRepo });

    const res = await app.inject({ method: 'GET', url: '/audit/actor/analyst%40example.com', headers: { 'x-tenant-id': 'acme' } });
    const body = JSON.parse(res.body);

    expect(body.events).toHaveLength(1);
    expect(body.events[0].type).toBe('PII_REGISTRY_DECLARED');

    await app.close();
  });

  it('GET /audit/resource/:resourceId returns both declared and modified events for that resource', async () => {
    const piiRegistryService = new PiiRegistryService([declaredEntry]);
    const deletionRequestRepo = makeFakeDeletionRequestRepo([]);

    const app = Fastify({ logger: false });
    await app.register(auditRoutes, { piiRegistryService, deletionRequestRepo });

    const encoded = encodeURIComponent(declaredEntry.resourceId);
    const res = await app.inject({ method: 'GET', url: `/audit/resource/${encoded}`, headers: { 'x-tenant-id': 'acme' } });
    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.body);

    expect(body.count).toBe(2);
    expect(body.events.map((e: { type: string }) => e.type).sort()).toEqual(['PII_REGISTRY_DECLARED', 'PII_REGISTRY_MODIFIED']);

    await app.close();
  });

  it('GET /audit/resource/:resourceId returns 404 for an unknown resource', async () => {
    const piiRegistryService = new PiiRegistryService([]);
    const deletionRequestRepo = makeFakeDeletionRequestRepo([]);

    const app = Fastify({ logger: false });
    await app.register(auditRoutes, { piiRegistryService, deletionRequestRepo });

    const res = await app.inject({ method: 'GET', url: '/audit/resource/bigquery%3Anope', headers: { 'x-tenant-id': 'acme' } });
    expect(res.statusCode).toBe(404);

    await app.close();
  });
});
