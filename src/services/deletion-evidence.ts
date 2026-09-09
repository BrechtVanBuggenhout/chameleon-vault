import type { DeletionRequest } from '../types/deletion-request.js';

/**
 * DELETION EVIDENCE ROLLUP.
 *
 * Aggregates a period's worth of deletion requests into the shape a
 * compliance auditor (SOC2/ISO27001-style sampling of a "data disposal"
 * control) wants to see: did every request in the period reach a
 * certificate, and if not, which ones didn't. Deliberately does not invent
 * a "stuck" threshold -- every non-CERTIFICATE_ISSUED request in the period
 * is surfaced plainly with its current status and age, for a human to judge.
 * Pure and unit-tested, same shape as pii-coverage.ts's computeCoverage.
 */

export interface IncompleteDeletionRequest {
  deletionRequestId: string;
  userId: string;
  status: DeletionRequest['status'];
  createdAt: string;
  ageHours: number;
}

export interface DeletionEvidenceReport {
  totalRequests: number;
  certificateIssued: number;
  incomplete: IncompleteDeletionRequest[];
  partialFailures: number;
  medianTimeToCertificateHours: number | null;
}

function hoursBetween(from: Date, to: Date): number {
  return (to.getTime() - from.getTime()) / (1000 * 60 * 60);
}

function median(values: number[]): number | null {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid];
}

export function computeDeletionEvidence(requests: DeletionRequest[], now: Date = new Date()): DeletionEvidenceReport {
  const incomplete: IncompleteDeletionRequest[] = [];
  const timeToCertificateHours: number[] = [];
  let certificateIssued = 0;
  let partialFailures = 0;

  for (const request of requests) {
    if (request.status === 'CASCADE_PARTIAL_FAILURE') {
      partialFailures += 1;
    }

    if (request.status === 'CERTIFICATE_ISSUED') {
      certificateIssued += 1;
      if (request.certificate_issued_at) {
        timeToCertificateHours.push(hoursBetween(new Date(request.created_at), new Date(request.certificate_issued_at)));
      }
      continue;
    }

    incomplete.push({
      deletionRequestId: request.deletion_request_id,
      userId: request.user_id,
      status: request.status,
      createdAt: new Date(request.created_at).toISOString(),
      ageHours: Math.round(hoursBetween(new Date(request.created_at), now) * 10) / 10,
    });
  }

  return {
    totalRequests: requests.length,
    certificateIssued,
    incomplete,
    partialFailures,
    medianTimeToCertificateHours: median(timeToCertificateHours),
  };
}
