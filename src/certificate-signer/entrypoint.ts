import { getRequiredEnv } from '../config/env.js';
import { CertificateSigner } from './sign.js';
import { CertificateSignerFirestoreClient } from './firestore-client.js';
import { LocalSigningKmsClient } from './kms-client.js';
import { GoogleIdTokenVerifier } from './auth.js';
import { createServer } from './server.js';
import { createLogger } from './logger.js';
import { configureWorkloadIdentityCredentialsIfPresent } from './gcp-credentials.js';

const logger = createLogger('certificate-signer-entrypoint');

// Must run before any GCP client is constructed below -- see
// gcp-credentials.ts for why.
configureWorkloadIdentityCredentialsIfPresent();

const projectId = getRequiredEnv('GCP_PROJECT_ID');
const kmsRegion = getRequiredEnv('CLOUD_KMS_REGION');
const signingKmsKeyRing = getRequiredEnv('CLOUD_KMS_SIGNING_KEY_RING');
const signingKmsKeyName = getRequiredEnv('CLOUD_KMS_SIGNING_KEY_NAME');
const firestoreCollection = getRequiredEnv('FIRESTORE_COLLECTION');
const firestoreDeletionRequestCollection = getRequiredEnv('FIRESTORE_DELETION_REQUEST_COLLECTION');
const firestoreDatabaseId = process.env.FIRESTORE_DATABASE_ID;
// Same collection the monolith's declare API and main.ts's
// CertificateSignerFirestoreClient wiring both use -- see main.ts's
// comment on why this is read once, in one place, rather than risking two
// deployments disagreeing about which collection is real.
const declarationCollection = process.env.FIRESTORE_PII_DECLARATION_COLLECTION || 'pii_registry_declarations';
const idTokenAudience = getRequiredEnv('ID_TOKEN_AUDIENCE');
const allowedCallerEmail = getRequiredEnv('ALLOWED_CALLER_EMAIL');
const port = Number(process.env.PORT ?? '8080');

const firestoreClient = new CertificateSignerFirestoreClient(
  projectId,
  firestoreCollection,
  firestoreDeletionRequestCollection,
  declarationCollection,
  firestoreDatabaseId
);
const kmsClient = new LocalSigningKmsClient(projectId, kmsRegion, signingKmsKeyRing, signingKmsKeyName);
const signer = new CertificateSigner(firestoreClient, kmsClient);

const server = createServer(signer, new GoogleIdTokenVerifier(), { idTokenAudience, allowedCallerEmail });
server.listen(port, () => {
  logger.info({ port }, 'certificate-signer listening');
});
