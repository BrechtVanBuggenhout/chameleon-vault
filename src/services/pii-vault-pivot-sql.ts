/**
 * Shared SQL-generation for pivoting pii_vault's long/flattened rows
 * (tenant_id, user_id, resource_id, field_name, key_id, token,
 * encrypted_value, synced_at -- one row per user+field) into one decrypted
 * column per declared field. Used by both DecryptedViewService (a view
 * built purely on pii_vault) and SourceRedactionService's SHADOW_COPY
 * strategy (a view joining pii_vault against a customer's own source
 * table) -- factored out so both stay in sync on the one thing that
 * actually matters here: correct, safely-quoted SQL.
 *
 * batchDecryptFunctionRef MUST be backtick-quoted by the caller's context
 * (or here) before use -- BigQuery parses an unquoted hyphenated project id
 * (every real GCP project id) as subtraction, not an identifier. Confirmed
 * live 2026-08-02 (chameleon-key-vault#30): every real declare failed with
 * "Syntax error: Expected ')' but got identifier" until this was fixed.
 */
export function escapeSqlStringLiteral(value: string): string {
  return value.replace(/'/g, "''");
}

/**
 * One ARRAY_AGG(...) expression per declared field, each picking that
 * field's most recently synced, live-decrypted value for whatever row
 * group the caller's surrounding GROUP BY user_id produces. Only
 * encrypted_value (real, reversible ciphertext) is ever decrypted --
 * never token, which is a one-way HMAC join key.
 */
export function buildPiiVaultPivotColumns(declaredFields: string[], batchDecryptFunctionRef: string): string[] {
  return declaredFields.map((field) => {
    const fieldLiteral = escapeSqlStringLiteral(field);
    return (
      `ARRAY_AGG(IF(field_name = '${fieldLiteral}', ` +
      `\`${batchDecryptFunctionRef}\`(CAST(encrypted_value AS STRING), user_id, tenant_id), NULL) ` +
      `IGNORE NULLS ORDER BY synced_at DESC LIMIT 1)[SAFE_OFFSET(0)] AS ${field}`
    );
  });
}
