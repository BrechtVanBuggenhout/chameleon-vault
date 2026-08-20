import type { PiiRegistryEntry, SourceRedactionStrategy } from '../types/pii-registry.js';

/**
 * The one place any consumer should ask "which source-redaction strategies
 * does this resource have?" -- resolves the new, combinable
 * sourceRedactionStrategies array if present, otherwise falls back to
 * wrapping the legacy single-value sourceRedactionStrategy field (dropping
 * 'NONE', which was that field's "nothing" value but is never a member of
 * the array). No Firestore migration needed for this: existing documents
 * declared before the array field existed just take this fallback path
 * forever, or until someone re-saves them through buildManualEntry, which
 * always writes the array form going forward.
 */
export function resolveSourceRedactionStrategies(
  entry: Pick<PiiRegistryEntry, 'sourceRedactionStrategy' | 'sourceRedactionStrategies'>
): SourceRedactionStrategy[] {
  if (entry.sourceRedactionStrategies) {
    return entry.sourceRedactionStrategies;
  }
  return entry.sourceRedactionStrategy && entry.sourceRedactionStrategy !== 'NONE'
    ? [entry.sourceRedactionStrategy]
    : [];
}

export function hasSourceRedactionStrategy(
  entry: Pick<PiiRegistryEntry, 'sourceRedactionStrategy' | 'sourceRedactionStrategies'>,
  strategy: SourceRedactionStrategy
): boolean {
  return resolveSourceRedactionStrategies(entry).includes(strategy);
}
