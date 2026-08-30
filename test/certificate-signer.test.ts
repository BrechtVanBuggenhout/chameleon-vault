import * as crypto from 'crypto';
import { jest, describe, it, expect, beforeEach } from '@jest/globals';

import { CertificateSignerFirestoreClient } from '../src/certificate-signer/firestore-client.js';
import { CloudKMSClient } from '../src/gcp/cloud-kms.js';
import { DeletionRequest } from '../src/types/deletion-request.js';

const { CertificateSigner } = await import('../src/certificate-signer/sign.js');

// A real PEM keypair -- generateClaims's keyFingerprint step runs
// crypto.createPublicKey() on whatever getPublicKey() returns, so a fake
// string won't do.
const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();

describe('CertificateSigner.generateClaims', () => {
  let signer: InstanceType<typeof CertificateSigner>;
  let mockFirestoreClient: {
    getKeyStatus: jest.Mock;
    getDeletionRequest: jest.Mock;
    getLatestCompletedDeletionRequestForUser: jest.Mock;
  };
  let mockKmsClient: { getCryptoKeyPath: jest.Mock; getNewestEnabledVersion: jest.Mock; getPublicKey: jest.Mock };
  let baseRequest: DeletionRequest;

  beforeEach(() => {
    baseRequest = {
      deletion_request_id: 'del-1',
      tenant_id: 'default-tenant',
      user_id: 'user-1',
      status: 'CASCADE_COMPLETE',
      created_at: new Date(),
      status_history: [],
      janitor_wipes: [],
    };

    mockFirestoreClient = {
      getKeyStatus: jest.fn().mockResolvedValue({ status: 'SHREDDED', created_at: '2026-01-01T00:00:00Z', shredAt: '2026-08-16T20:39:06.717Z' }),
      getDeletionRequest: jest.fn(async () => ({ ...baseRequest })),
      getLatestCompletedDeletionRequestForUser: jest.fn(async () => ({ ...baseRequest })),
    };
    mockKmsClient = {
      getCryptoKeyPath: jest.fn().mockReturnValue('projects/p/locations/l/keyRings/r/cryptoKeys/k'),
      getNewestEnabledVersion: jest.fn().mockResolvedValue('projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1'),
      getPublicKey: jest.fn().mockResolvedValue(publicKeyPem),
    };

    signer = new CertificateSigner(
      mockFirestoreClient as unknown as CertificateSignerFirestoreClient,
      mockKmsClient as unknown as CloudKMSClient
    );
  });

  it('labels a source-redaction wipe with rowsAffected: 0 as CONFIRMED_ABSENT, not ERASED', async () => {
    // Reproduces a real false-positive found live on Immoscoop 2026-08-17:
    // a REDACT_IN_PLACE UPDATE whose WHERE clause matched zero rows was
    // certified as "ERASED" because only janitor's recordsFound was
    // checked, never source-redaction's rowsAffected.
    baseRequest.janitor_wipes = [
      {
        destination: 'bigquery:immoscoop-datawarehouse-raw.DATA.agencyAndOfficeMigration',
        status: 'SUCCEEDED',
        updated_at: new Date('2026-08-16T20:39:06.717Z'),
        details: { rowsAffected: 0 },
      },
    ];

    const claims = await signer.generateClaims({
      userId: 'user-1', tenantId: 'default-tenant', deletionRequestId: 'del-1',
      ghostDataSummary: [], knownDestinationTypes: ['hubspot', 'salesforce'],
    });

    expect(claims.lineageSummary).toEqual([
      expect.objectContaining({
        system: 'bigquery:immoscoop-datawarehouse-raw.DATA.agencyAndOfficeMigration',
        status: 'CONFIRMED_ABSENT',
      }),
    ]);
  });

  it('still labels a real source-redaction wipe (rowsAffected > 0) as ERASED', async () => {
    baseRequest.janitor_wipes = [
      {
        destination: 'bigquery:acme.crm.contacts',
        status: 'SUCCEEDED',
        updated_at: new Date('2026-08-16T20:39:06.717Z'),
        details: { rowsAffected: 3 },
      },
    ];

    const claims = await signer.generateClaims({
      userId: 'user-1', tenantId: 'default-tenant', deletionRequestId: 'del-1',
      ghostDataSummary: [], knownDestinationTypes: ['hubspot', 'salesforce'],
    });

    expect(claims.lineageSummary).toEqual([
      expect.objectContaining({ system: 'bigquery:acme.crm.contacts', status: 'ERASED' }),
    ]);
  });

  it('still labels a janitor/SaaS wipe with recordsFound: 0 as CONFIRMED_ABSENT (existing behavior preserved)', async () => {
    baseRequest.janitor_wipes = [
      { destination: 'hubspot', status: 'SUCCEEDED', updated_at: new Date(), details: { recordsFound: 0 } },
    ];

    const claims = await signer.generateClaims({
      userId: 'user-1', tenantId: 'default-tenant', deletionRequestId: 'del-1',
      ghostDataSummary: [], knownDestinationTypes: ['hubspot', 'salesforce'],
    });

    expect(claims.lineageSummary).toEqual([
      expect.objectContaining({ system: 'hubspot', status: 'CONFIRMED_ABSENT' }),
    ]);
  });

  it('renders a real ISO timestamp for a plain Date, not "[object Object]"', async () => {
    const when = new Date('2026-08-16T20:39:06.717Z');
    baseRequest.janitor_wipes = [
      { destination: 'hubspot', status: 'SUCCEEDED', updated_at: when, details: {} },
    ];

    const claims = await signer.generateClaims({
      userId: 'user-1', tenantId: 'default-tenant', deletionRequestId: 'del-1',
      ghostDataSummary: [], knownDestinationTypes: ['hubspot', 'salesforce'],
    });

    expect(claims.lineageSummary[0].timestamp).toBe('2026-08-16T20:39:06.717Z');
  });

  it('renders a real ISO timestamp for a Firestore-Timestamp-shaped value, not "[object Object]"', async () => {
    // Reproduces the exact bug found in a real issued certificate: Firestore's
    // Node SDK reads timestamp fields back as its own Timestamp class, which
    // is not `instanceof Date` and has no toString() override -- String()
    // on it silently produces "[object Object]" instead of throwing.
    const when = new Date('2026-08-16T20:39:06.717Z');
    const firestoreTimestampShaped = { toDate: () => when };
    baseRequest.janitor_wipes = [
      { destination: 'hubspot', status: 'SUCCEEDED', updated_at: firestoreTimestampShaped as any, details: {} },
    ];

    const claims = await signer.generateClaims({
      userId: 'user-1', tenantId: 'default-tenant', deletionRequestId: 'del-1',
      ghostDataSummary: [], knownDestinationTypes: ['hubspot', 'salesforce'],
    });

    expect(claims.lineageSummary[0].timestamp).toBe('2026-08-16T20:39:06.717Z');
    expect(claims.lineageSummary[0].timestamp).not.toBe('[object Object]');
  });

  it('only ever includes SUCCEEDED wipes, never a FAILED one, in lineageSummary', async () => {
    baseRequest.janitor_wipes = [
      { destination: 'hubspot', status: 'SUCCEEDED', updated_at: new Date(), details: {} },
      { destination: 'salesforce', status: 'FAILED', updated_at: new Date(), details: { error: 'timeout' } },
    ];

    const claims = await signer.generateClaims({
      userId: 'user-1', tenantId: 'default-tenant', deletionRequestId: 'del-1',
      ghostDataSummary: [], knownDestinationTypes: ['hubspot', 'salesforce'],
    });

    expect(claims.lineageSummary).toHaveLength(1);
    expect(claims.lineageSummary[0].system).toBe('hubspot');
  });

  it('throws when the key is not shredded -- independently re-checked, never trusted from a caller', async () => {
    mockFirestoreClient.getKeyStatus.mockResolvedValue({ status: 'ACTIVE', created_at: '2026-01-01T00:00:00Z' });

    await expect(signer.generateClaims({
      userId: 'user-1', tenantId: 'default-tenant', deletionRequestId: 'del-1',
      ghostDataSummary: [], knownDestinationTypes: [],
    })).rejects.toThrow('not shredded');
  });

  it('throws when no completed cascade is found -- independently re-checked, never trusted from a caller', async () => {
    mockFirestoreClient.getDeletionRequest.mockResolvedValue(null);

    await expect(signer.generateClaims({
      userId: 'user-1', tenantId: 'default-tenant', deletionRequestId: 'del-1',
      ghostDataSummary: [], knownDestinationTypes: [],
    })).rejects.toThrow('no completed deletion cascade');
  });

  it('embeds the real shred time (shredAt), not the certificate issuance time', async () => {
    // Regression test for a real bug found while writing this extraction:
    // the original FirestoreRegistry.getKeyStatus only ever set shred_at
    // (snake_case), never shredAt (camelCase), even though claims-building
    // reads keyStatus.shredAt -- silently falling back to "now" on every
    // certificate. CertificateSignerFirestoreClient sets both; this
    // confirms generateClaims actually uses the real value when present.
    mockFirestoreClient.getKeyStatus.mockResolvedValue({
      status: 'SHREDDED', created_at: '2026-01-01T00:00:00Z', shredAt: '2026-08-16T20:39:06.717Z',
    });

    const claims = await signer.generateClaims({
      userId: 'user-1', tenantId: 'default-tenant', deletionRequestId: 'del-1',
      ghostDataSummary: [], knownDestinationTypes: [],
    });

    expect(claims.shredDate).toBe('2026-08-16T20:39:06.717Z');
    expect(claims.shred_date).toBe('2026-08-16T20:39:06.717Z');
  });

  it('passes ghostDataSummary and knownDestinationTypes through as given -- these are caller-supplied, not re-derived', async () => {
    const ghostDataSummary = [
      { scope: 'RESOURCE_LEVEL' as const, resourceId: 'bigquery:ds.t', system: 'bigquery', lastSeen: '2026-01-01T00:00:00Z' },
    ];

    const claims = await signer.generateClaims({
      userId: 'user-1', tenantId: 'default-tenant', deletionRequestId: 'del-1',
      ghostDataSummary, knownDestinationTypes: ['hubspot', 'salesforce', 'custom-connector'],
    });

    expect(claims.ghostDataSummary).toEqual(ghostDataSummary);
    expect(claims.ghost_data_summary).toEqual(ghostDataSummary);
    expect(claims.lineageCoverage.knownDestinationTypes).toEqual(['hubspot', 'salesforce', 'custom-connector']);
    expect(claims.ghostDataScanCoverage).toBe('NOT_TRACKED');
  });
});

describe('CertificateSigner.signClaims', () => {
  it('signs via KMS using the current key version as kid, and returns a matching sha256 hash', async () => {
    const mockFirestoreClient = {
      getKeyStatus: jest.fn(), getDeletionRequest: jest.fn(), getLatestCompletedDeletionRequestForUser: jest.fn(),
    };
    const mockKmsClient = {
      getCryptoKeyPath: jest.fn().mockReturnValue('projects/p/locations/l/keyRings/r/cryptoKeys/k'),
      getNewestEnabledVersion: jest.fn().mockResolvedValue('projects/p/.../cryptoKeyVersions/3'),
      asymmetricSign: jest.fn().mockResolvedValue('fake-signature-base64url'),
    };
    const signer = new CertificateSigner(
      mockFirestoreClient as unknown as CertificateSignerFirestoreClient,
      mockKmsClient as unknown as CloudKMSClient
    );

    const claims = { iss: 'Chameleon Key Vault', sub: 'user-1' } as any;
    const { certificate, certificateHash } = await signer.signClaims(claims);

    const [headerB64, payloadB64, signatureB64] = certificate.split('.');
    const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString());
    expect(header).toEqual({ alg: 'PS256', typ: 'JWT', kid: 'projects/p/.../cryptoKeyVersions/3' });
    expect(JSON.parse(Buffer.from(payloadB64, 'base64url').toString())).toEqual(claims);
    expect(signatureB64).toBe('fake-signature-base64url');

    expect(certificateHash).toBe(crypto.createHash('sha256').update(certificate).digest('hex'));
    expect(mockKmsClient.asymmetricSign).toHaveBeenCalledWith(`${headerB64}.${payloadB64}`, 'projects/p/.../cryptoKeyVersions/3');
  });
});

describe('CertificateSigner.invalidateSigningKeyCache', () => {
  it('forces the next sign to re-fetch the current key version instead of using a cached one', async () => {
    const mockFirestoreClient = {
      getKeyStatus: jest.fn(), getDeletionRequest: jest.fn(), getLatestCompletedDeletionRequestForUser: jest.fn(),
    };
    const mockKmsClient = {
      getCryptoKeyPath: jest.fn().mockReturnValue('projects/p/locations/l/keyRings/r/cryptoKeys/k'),
      getNewestEnabledVersion: jest.fn()
        .mockResolvedValueOnce('projects/p/.../cryptoKeyVersions/1')
        .mockResolvedValueOnce('projects/p/.../cryptoKeyVersions/2'),
      asymmetricSign: jest.fn().mockResolvedValue('sig'),
    };
    const signer = new CertificateSigner(
      mockFirestoreClient as unknown as CertificateSignerFirestoreClient,
      mockKmsClient as unknown as CloudKMSClient
    );

    const first = await signer.signClaims({} as any);
    expect(first.certificate.split('.')[0]).toContain(''); // sanity: produced a token
    const firstHeader = JSON.parse(Buffer.from(first.certificate.split('.')[0], 'base64url').toString());
    expect(firstHeader.kid).toBe('projects/p/.../cryptoKeyVersions/1');

    // Without invalidation, the cache would still return version 1 here.
    signer.invalidateSigningKeyCache();

    const second = await signer.signClaims({} as any);
    const secondHeader = JSON.parse(Buffer.from(second.certificate.split('.')[0], 'base64url').toString());
    expect(secondHeader.kid).toBe('projects/p/.../cryptoKeyVersions/2');
    expect(mockKmsClient.getNewestEnabledVersion).toHaveBeenCalledTimes(2);
  });
});
