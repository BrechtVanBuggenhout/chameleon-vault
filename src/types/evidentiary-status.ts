/**
 * Per-mechanism evidentiary status for one specific certificate -- what
 * actually held for this certificate, not what the scheme is capable of in
 * general. Deliberately excludes a "signature" field: the server reporting
 * its own signature as valid proves nothing an external verifier doesn't
 * already independently check via JWKS, so a self-graded field here would
 * be misleading rather than merely redundant.
 *
 * hashChain reports structural linkage (read from the certificate's own
 * previousCertificateHash/chainSequence claims), not full chain-integrity
 * verification back to genesis -- that's deliberately left to independent
 * verification (scripts/verify-cert.ts), the same way the signature is.
 * Reporting "the whole chain is valid" from the issuer's own database would
 * undercut the one property this scheme is supposed to let a skeptical
 * party check without trusting Chameleon.
 *
 * timestamp/transparencyLog carry a third state beyond the underlying
 * client's own OBTAINED/FAILED and PUBLISHED/FAILED: NOT_ATTEMPTED, for
 * deployments where TsaClient/RekorClient aren't configured, and for the
 * unchained fallback certificate getCertificateForUser signs on demand
 * when a request hasn't reached CERTIFICATE_ISSUED yet -- neither
 * mechanism is ever attempted on that path.
 *
 * hardwareAttestation is a constant, not a computed field: no code path
 * produces real attestation data today (TEE/Confidential Space integration
 * shipped but is left disabled -- GCP's Attestation Service currently
 * rejects the SEV-SNP attestation type outright, see
 * chameleon-infra-gcp's certificate-signer-tee.tf). One line to change
 * if that ever ships for real.
 */
export interface EvidentiaryStatus {
  hashChain: {
    linked: boolean;
    chainSequence: number | null;
  };
  timestamp: 'OBTAINED' | 'FAILED' | 'NOT_ATTEMPTED';
  transparencyLog: 'PUBLISHED' | 'FAILED' | 'NOT_ATTEMPTED';
  hardwareAttestation: 'NOT_AVAILABLE';
}
