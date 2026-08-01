// A customer-declared, ephemeral, decrypt-on-query BigQuery Authorized View.
// Never a materialized table -- the view definition calls back into
// batch-decrypt at query time, so nothing here ever holds plaintext at rest.
// See DecryptedViewsRepository and decrypted-view-service.ts.
export interface DecryptedViewDeclaration {
  tenant_id: string;
  view_name: string;
  // Which declared PII registry resource this view sources from, e.g.
  // bigquery:project.dataset.raw_users -- must already be a registered,
  // encrypted/tokenized resource (never an undeclared one).
  source_resource_id: string;
  // Which of that resource's declared PII fields this view exposes decrypted.
  declared_fields: string[];
  // Required, not optional: the GDPR purpose-limitation record -- why this
  // view needs to exist, not just a technical toggle.
  business_justification: string;
  created_by: string;
  bigquery_dataset: string;
  bigquery_view_name: string;
  status: 'active' | 'revoked';
  created_at: Date;
  revoked_at?: Date;
  revoked_by?: string;
}
