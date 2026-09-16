import * as crypto from 'crypto';
import axios from 'axios';
import type { RekorLogEntryInfo } from '../gcp/rekor-client.js';

export type RekorVerificationResult =
  | { outcome: 'VALID'; entryUuid: string; logIndex?: number; rekorUrl: string }
  | { outcome: 'INVALID'; reason: string }
  | { outcome: 'ABSENT' }
  | { outcome: 'RECORDED_FAILURE' };

/**
 * Independently confirms a Rekor transparency-log entry actually exists and
 * attests to the right content -- never trusts the stored status string
 * alone, the same way verifyTsaTimestamp (tsa-verify.ts) never trusts a
 * stored hash. Fetches the entry live from Rekor's own public API (GET
 * /api/v1/log/entries/{uuid}) and recomputes the digest Chameleon should
 * have submitted at issuance -- sha256 of the canonical two-key
 * {certificateHash, previousCertificateHash} JSON RekorClient.
 * publishCertificateHash actually signs and submits -- comparing it
 * against what the log recorded. A matching digest means this exact
 * (certificateHash, previousCertificateHash) pair was really published to
 * a log outside Chameleon's own control, at the position Chameleon claims.
 */
export async function verifyRekorEntry(
  certificateHash: string,
  previousCertificateHash: string | null,
  rekorEntry: RekorLogEntryInfo | undefined
): Promise<RekorVerificationResult> {
  if (!rekorEntry) return { outcome: 'ABSENT' };
  if (rekorEntry.status === 'FAILED') return { outcome: 'RECORDED_FAILURE' };
  if (!rekorEntry.entryUuid) {
    return { outcome: 'INVALID', reason: 'status PUBLISHED but no entryUuid stored' };
  }

  try {
    const res = await axios.get(`${rekorEntry.rekorUrl}/api/v1/log/entries/${rekorEntry.entryUuid}`, {
      timeout: 5_000,
      validateStatus: () => true,
    });

    if (res.status !== 200) {
      return { outcome: 'INVALID', reason: `Rekor lookup returned HTTP ${res.status} for entry ${rekorEntry.entryUuid}` };
    }

    // Keyed by entry UUID, same response shape as the publish call --
    // confirmed against the real public Rekor API. Falls back to the
    // first (only) value in case Rekor ever returns it under a
    // differently-cased key.
    const entry = res.data?.[rekorEntry.entryUuid] ?? Object.values(res.data ?? {})[0];
    if (!entry?.body) {
      return { outcome: 'INVALID', reason: 'Rekor entry response missing body' };
    }

    const decoded = JSON.parse(Buffer.from(entry.body, 'base64').toString('utf-8'));
    const storedHash = decoded?.spec?.data?.hash;
    if (!storedHash?.algorithm || !storedHash?.value) {
      return { outcome: 'INVALID', reason: 'Rekor entry body missing spec.data.hash' };
    }
    if (storedHash.algorithm !== 'sha256') {
      return { outcome: 'INVALID', reason: `unexpected hash algorithm ${storedHash.algorithm} (expected sha256)` };
    }

    const expectedPayload = JSON.stringify({ certificateHash, previousCertificateHash });
    const expectedDigest = crypto.createHash('sha256').update(expectedPayload).digest('hex');

    if (storedHash.value !== expectedDigest) {
      return {
        outcome: 'INVALID',
        reason: 'Rekor entry\'s recorded hash does not match sha256({certificateHash, previousCertificateHash}) for this certificate -- either a different certificate was published under this uuid, or the log entry was tampered with',
      };
    }

    return {
      outcome: 'VALID',
      entryUuid: rekorEntry.entryUuid,
      logIndex: rekorEntry.logIndex,
      rekorUrl: rekorEntry.rekorUrl,
    };
  } catch (error) {
    return { outcome: 'INVALID', reason: error instanceof Error ? error.message : String(error) };
  }
}
