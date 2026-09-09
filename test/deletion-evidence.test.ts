import { describe, expect, it } from '@jest/globals';
import { computeDeletionEvidence } from '../src/services/deletion-evidence.js';
import type { DeletionRequest, DeletionRequestStatus } from '../src/types/deletion-request.js';

function request(overrides: Partial<DeletionRequest> = {}): DeletionRequest {
  return {
    deletion_request_id: 'req-1',
    tenant_id: 'default-tenant',
    user_id: 'user-1',
    status: 'CERTIFICATE_ISSUED' as DeletionRequestStatus,
    created_at: new Date('2026-09-01T00:00:00.000Z'),
    status_history: [],
    janitor_wipes: [],
    ...overrides,
  };
}

describe('computeDeletionEvidence', () => {
  it('splits mixed statuses into certificateIssued vs incomplete correctly', () => {
    const requests = [
      request({ deletion_request_id: 'a', status: 'CERTIFICATE_ISSUED', certificate_issued_at: new Date('2026-09-01T02:00:00.000Z') }),
      request({ deletion_request_id: 'b', status: 'CASCADE_PENDING' }),
      request({ deletion_request_id: 'c', status: 'KEY_DESTROYED' }),
    ];

    const report = computeDeletionEvidence(requests, new Date('2026-09-02T00:00:00.000Z'));

    expect(report.totalRequests).toBe(3);
    expect(report.certificateIssued).toBe(1);
    expect(report.incomplete.map((r) => r.deletionRequestId).sort()).toEqual(['b', 'c']);
  });

  it('counts a CASCADE_PARTIAL_FAILURE row in both incomplete and partialFailures', () => {
    const requests = [request({ deletion_request_id: 'x', status: 'CASCADE_PARTIAL_FAILURE' })];

    const report = computeDeletionEvidence(requests, new Date('2026-09-02T00:00:00.000Z'));

    expect(report.partialFailures).toBe(1);
    expect(report.incomplete).toHaveLength(1);
    expect(report.incomplete[0].deletionRequestId).toBe('x');
    expect(report.incomplete[0].status).toBe('CASCADE_PARTIAL_FAILURE');
  });

  it('returns an all-zero result for an empty period, not an error', () => {
    const report = computeDeletionEvidence([]);

    expect(report).toEqual({
      totalRequests: 0,
      certificateIssued: 0,
      incomplete: [],
      partialFailures: 0,
      medianTimeToCertificateHours: null,
    });
  });

  it('handles a real Firestore Timestamp-shaped object (toDate(), not a Date instance) without throwing', () => {
    // doc.data() returns Firestore Timestamp instances for date fields at
    // runtime, not native Dates -- confirmed live against the real dev
    // deployment (this exact shape produced an empty-object RangeError
    // before toDate() was added). A fake Timestamp here reproduces that.
    class FakeTimestamp {
      constructor(private readonly date: Date) {}
      toDate() {
        return this.date;
      }
    }

    const requests = [
      request({
        deletion_request_id: 'ts-1',
        status: 'CASCADE_PENDING',
        created_at: new FakeTimestamp(new Date('2026-09-01T00:00:00.000Z')) as unknown as Date,
      }),
    ];

    const report = computeDeletionEvidence(requests, new Date('2026-09-01T05:00:00.000Z'));

    expect(report.incomplete).toHaveLength(1);
    expect(report.incomplete[0].createdAt).toBe('2026-09-01T00:00:00.000Z');
    expect(report.incomplete[0].ageHours).toBe(5);
  });

  it('computes the median time-to-certificate correctly for an odd count', () => {
    const requests = [
      request({ deletion_request_id: 'a', created_at: new Date('2026-09-01T00:00:00.000Z'), certificate_issued_at: new Date('2026-09-01T01:00:00.000Z') }), // 1h
      request({ deletion_request_id: 'b', created_at: new Date('2026-09-01T00:00:00.000Z'), certificate_issued_at: new Date('2026-09-01T05:00:00.000Z') }), // 5h
      request({ deletion_request_id: 'c', created_at: new Date('2026-09-01T00:00:00.000Z'), certificate_issued_at: new Date('2026-09-01T09:00:00.000Z') }), // 9h
    ];

    const report = computeDeletionEvidence(requests);

    expect(report.medianTimeToCertificateHours).toBe(5);
  });

  it('computes the median time-to-certificate correctly for an even count', () => {
    const requests = [
      request({ deletion_request_id: 'a', created_at: new Date('2026-09-01T00:00:00.000Z'), certificate_issued_at: new Date('2026-09-01T01:00:00.000Z') }), // 1h
      request({ deletion_request_id: 'b', created_at: new Date('2026-09-01T00:00:00.000Z'), certificate_issued_at: new Date('2026-09-01T03:00:00.000Z') }), // 3h
      request({ deletion_request_id: 'c', created_at: new Date('2026-09-01T00:00:00.000Z'), certificate_issued_at: new Date('2026-09-01T05:00:00.000Z') }), // 5h
      request({ deletion_request_id: 'd', created_at: new Date('2026-09-01T00:00:00.000Z'), certificate_issued_at: new Date('2026-09-01T09:00:00.000Z') }), // 9h
    ];

    const report = computeDeletionEvidence(requests);

    expect(report.medianTimeToCertificateHours).toBe(4);
  });
});
