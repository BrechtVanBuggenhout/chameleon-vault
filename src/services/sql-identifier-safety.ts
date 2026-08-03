// Real BigQuery column/table identifiers only -- validated before use in a
// generated SQL string. BigQuery has no way to parameterize an identifier
// (only values), so this is the only guard between a malformed/malicious
// declaration and a broken or dangerous statement. Shared by
// SourceRedactionService's REDACT_IN_PLACE (a real write) and SHADOW_COPY
// (a view referencing the customer's own table) code paths.
const SAFE_IDENTIFIER = /^[a-zA-Z_][a-zA-Z0-9_]*$/;

export function assertSafeIdentifiers(identifiers: string[]): void {
  for (const identifier of identifiers) {
    if (!SAFE_IDENTIFIER.test(identifier)) {
      throw new Error(`Refusing to use "${identifier}" as a SQL identifier: not a safe column/table name.`);
    }
  }
}
