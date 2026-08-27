// Marker field for log lines that should land in the Bucket-Lock-protected
// audit_logs bucket -- matched by the Cloud Logging sink filter in
// chameleon-infra-gcp/audit_logging.tf (jsonPayload.certificateChainAnchor=true).
// Shared here so every anchor-worthy event (certificate chain appends,
// signing-key rotation) uses the exact same literal instead of each call
// site hand-copying the string and risking drift.
export const CHAIN_ANCHOR_MARKER = 'certificateChainAnchor';

export type AuditEventType = 'certificate_chain_append' | 'signing_key_rotated';
