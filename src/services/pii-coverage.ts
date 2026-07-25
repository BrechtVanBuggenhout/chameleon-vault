import type { PiiClassification, PiiRegistryEntry } from '../types/pii-registry.js';
import type { WarehouseDiscoveryFinding } from '../types/lineage.js';

/**
 * Crypto-shred COVERAGE SCORE.
 *
 * Classifies every known PII resource into PROTECTED / PARTIAL / EXPOSED and rolls them
 * up into a single risk-weighted percentage — the "% of your PII that is crypto-shreddable
 * vs at-risk" number. Metadata only; composes the registry, its policy evaluation, and the
 * crawler's undeclared findings. All functions here are pure and unit-tested.
 */

export type CoverageState = 'PROTECTED' | 'PARTIAL' | 'EXPOSED';

export interface CoverageItem {
  resourceId: string;
  system: string;
  state: CoverageState;
  weight: number;
  reasons: string[];
}

export interface CoverageReport {
  score: number; // 0..100
  counts: { protected: number; partial: number; exposed: number; total: number };
  weights: { protected: number; partial: number; exposed: number; total: number };
  items: CoverageItem[];
}

// Risk weight per field classification (most→least sensitive).
const FIELD_SENSITIVITY: Record<PiiClassification, number> = {
  DIRECT_IDENTIFIER: 3,
  SENSITIVE: 3,
  CONTACT: 2,
  QUASI_IDENTIFIER: 2,
  BEHAVIORAL: 1,
  SYSTEM_IDENTIFIER: 0.5,
};

/** Risk weight of a declared resource = sum of its field sensitivities (min 0.5). */
export function entryWeight(entry: PiiRegistryEntry): number {
  const sum = entry.piiFields.reduce((acc, field) => acc + (FIELD_SENSITIVITY[field.classification] ?? 1), 0);
  return Math.max(0.5, sum);
}

/** Rough sensitivity of an undeclared column, inferred from its name. */
export function columnSensitivity(name: string): number {
  const n = name.toLowerCase();
  const has = (...parts: string[]) => parts.some((p) => n.includes(p));
  if (has('email', 'ssn', 'social', 'dob', 'birth', 'passport', 'tax')) return 3;
  if (has('phone', 'mobile', 'name', 'address', 'street', 'city', 'zip', 'postal')) return 2;
  if (has('ip', 'geo', 'device', 'lat', 'lon')) return 2;
  if (has('_id', 'id', 'uuid', 'token')) return 0.5;
  return 2;
}

/** Estimated weight of an undeclared/drifted table (always EXPOSED). */
export function discoveryWeight(finding: WarehouseDiscoveryFinding): number {
  const sum = finding.columns.reduce((acc, col) => acc + columnSensitivity(col), 0);
  return Math.max(1, sum);
}

/**
 * Classify one declared resource. PROTECTED requires the full crypto-shred guarantee:
 * every PII field encrypted/tokenized, CRYPTO_SHRED strategy, a user identity link (so
 * a per-user key exists), and a passing policy. Anything declared-but-weaker is PARTIAL;
 * a failing policy is EXPOSED.
 *
 * SYSTEM_IDENTIFIER fields handled as HASH_SURROGATE are join keys, not recoverable
 * PII: crypto-shredding deliberately leaves the orphaned key behind while the PII it
 * points to becomes unreadable. They do not count against key-reversibility.
 */
function fieldIsShredSafe(f: PiiRegistryEntry['piiFields'][number]): boolean {
  if (f.handling === 'ENCRYPT' || f.handling === 'TOKENIZE') return true;
  return f.classification === 'SYSTEM_IDENTIFIER' && f.handling === 'HASH_SURROGATE';
}

export function classifyEntry(
  entry: PiiRegistryEntry,
  status: 'PASS' | 'WARN' | 'FAIL'
): { state: CoverageState; reasons: string[] } {
  if (status === 'FAIL') {
    return { state: 'EXPOSED', reasons: ['policy evaluation FAILs'] };
  }

  const reasons: string[] = [];
  const reversibleOnlyViaKey = entry.piiFields.length > 0 && entry.piiFields.every(fieldIsShredSafe);

  if (!reversibleOnlyViaKey) {
    const weak = entry.piiFields.filter((f) => !fieldIsShredSafe(f));
    reasons.push(`not key-reversible: ${weak.map((f) => `${f.name}=${f.handling}`).join(', ') || 'no fields'}`);
  }
  if (entry.deletionStrategy !== 'CRYPTO_SHRED') {
    reasons.push(`deletion strategy is ${entry.deletionStrategy}, not CRYPTO_SHRED`);
  }
  if (!entry.userIdColumn) {
    reasons.push('no user identity link (userIdColumn) — no per-user key');
  }
  if (status === 'WARN') {
    reasons.push('policy WARNs');
  }

  return reasons.length === 0 ? { state: 'PROTECTED', reasons: [] } : { state: 'PARTIAL', reasons };
}

/** Compose declared entries (with their policy status) and undeclared findings into items. */
export function toCoverageItems(
  entries: PiiRegistryEntry[],
  evaluate: (entry: PiiRegistryEntry) => 'PASS' | 'WARN' | 'FAIL',
  discovery: WarehouseDiscoveryFinding[]
): CoverageItem[] {
  const declared: CoverageItem[] = entries.map((entry) => {
    const { state, reasons } = classifyEntry(entry, evaluate(entry));
    return { resourceId: entry.resourceId, system: entry.system, state, weight: entryWeight(entry), reasons };
  });

  // Only surface undeclared findings not already covered by a declared entry.
  const declaredIds = new Set(entries.map((e) => e.resourceId));
  const undeclared: CoverageItem[] = discovery
    .filter((finding) => !declaredIds.has(finding.resourceId))
    .map((finding) => ({
      resourceId: finding.resourceId,
      system: finding.system,
      state: 'EXPOSED' as const,
      weight: discoveryWeight(finding),
      reasons: [finding.registryStatus === 'DRIFTED' ? 'schema drift vs registry' : 'discovered but undeclared'],
    }));

  return [...declared, ...undeclared];
}

/** Roll items into the weighted score. PARTIAL earns half credit. */
export function computeCoverage(items: CoverageItem[]): CoverageReport {
  const weights = { protected: 0, partial: 0, exposed: 0, total: 0 };
  const counts = { protected: 0, partial: 0, exposed: 0, total: items.length };

  for (const item of items) {
    weights.total += item.weight;
    if (item.state === 'PROTECTED') {
      weights.protected += item.weight;
      counts.protected += 1;
    } else if (item.state === 'PARTIAL') {
      weights.partial += item.weight;
      counts.partial += 1;
    } else {
      weights.exposed += item.weight;
      counts.exposed += 1;
    }
  }

  // No known PII surface ⇒ vacuously fully covered.
  const score = weights.total === 0 ? 100 : Math.round(((weights.protected + 0.5 * weights.partial) / weights.total) * 100);

  const order: Record<CoverageState, number> = { EXPOSED: 0, PARTIAL: 1, PROTECTED: 2 };
  const sorted = [...items].sort((a, b) => order[a.state] - order[b.state] || b.weight - a.weight);

  return { score, counts, weights, items: sorted };
}
