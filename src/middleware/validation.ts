import Joi from 'joi';

const lineageDataClassifications = [
  'PII',
  'ENCRYPTED_ONLY',
  'UNSTRUCTURED_CACHE',
  'GHOST_DATA',
  'AUDIT_TRAIL',
  // Metadata-only inventory events (e.g. WAREHOUSE_METADATA_DISCOVERED from the
  // warehouse crawler): column names and registry status, never values.
  'METADATA',
  'UNKNOWN',
];

// User ID validation: alphanumeric + hyphens, 1-64 chars
const userIdSchema = Joi.string()
  .pattern(/^[a-zA-Z0-9-_]+$/)
  .min(1)
  .max(64)
  .required()
  .messages({
    'string.pattern.base': 'userId must contain only alphanumeric characters, hyphens, and underscores',
    'string.min': 'userId must be at least 1 character',
    'string.max': 'userId must not exceed 64 characters',
  });

// Plaintext validation: non-empty string, max 10KB
const plaintextSchema = Joi.string()
  .min(1)
  .max(10240)
  .required()
  .messages({
    'string.min': 'Plaintext cannot be empty',
    'string.max': 'Plaintext must not exceed 10KB',
  });

export const encryptSchema = Joi.object({
  plaintext: plaintextSchema,
  userId: userIdSchema.optional(),
  user_id: userIdSchema.optional(),
})
  .or('userId', 'user_id')
  .required();

export const decryptSchema = Joi.object({
  ciphertext: Joi.string()
    .pattern(/^v\d+:[A-Za-z0-9+/=]+$/)
    .required()
    .messages({
      'string.pattern.base': 'Ciphertext must be in format v{version}:{base64}',
    }),
  userId: userIdSchema.optional(),
  user_id: userIdSchema.optional(),
})
  .or('userId', 'user_id')
  .required();

export const keyGenerateSchema = Joi.object({
  userId: userIdSchema.optional(),
  user_id: userIdSchema.optional(),
})
  .or('userId', 'user_id')
  .required();

export const keyRotateSchema = Joi.object({
  userId: userIdSchema.optional(),
  user_id: userIdSchema.optional(),
})
  .or('userId', 'user_id')
  .required();

export const keyShredSchema = Joi.object({
  userId: userIdSchema.optional(),
  user_id: userIdSchema.optional(),
  operationId: Joi.string().optional(),
  operation_id: Joi.string().optional(),
})
  .or('userId', 'user_id')
  .required();

export const keyStatusSchema = Joi.object({
  userId: userIdSchema,
}).required();

export const batchGenerateSchema = Joi.object({
  userIds: Joi.array().items(userIdSchema).min(1).max(1000).required(),
  tenantId: Joi.string().min(1).max(128).optional(),
  tenant_id: Joi.string().min(1).max(128).optional(),
}).required();

export const batchEncryptionContextSchema = Joi.object({
  userIds: Joi.array().items(userIdSchema).min(1).max(1000).required(),
  tenantId: Joi.string().min(1).max(128).optional(),
  tenant_id: Joi.string().min(1).max(128).optional(),
}).required();

export const lineageEventSchema = Joi.object({
  userId: userIdSchema.optional(),
  user_id: userIdSchema.optional(),
  source: Joi.string().min(1).max(128).required().messages({
    'string.min': 'Source cannot be empty',
    'string.max': 'Source must not exceed 128 characters',
  }),
  destination: Joi.string().min(1).max(128).required().messages({
    'string.min': 'Destination cannot be empty',
    'string.max': 'Destination must not exceed 128 characters',
  }),
  eventType: Joi.string().optional(),
  event_type: Joi.string().optional(),
  deletionRequestId: Joi.string().optional(),
  deletion_request_id: Joi.string().optional(),
  dataClassification: Joi.string().valid(...lineageDataClassifications).optional(),
  data_classification: Joi.string().valid(...lineageDataClassifications).optional(),
  retentionPolicy: Joi.string().valid('DELETE', 'REDACT', 'IMMUTABLE').optional(),
  retention_policy: Joi.string().valid('DELETE', 'REDACT', 'IMMUTABLE').optional(),
  context: Joi.object().unknown(true).optional(), // Allow any additional context metadata
  metadata: Joi.object().unknown(true).optional(), // Pipelines scanner alias for context metadata
})
  .or('userId', 'user_id')
  .required();

export const getEncryptionContextSchema = Joi.object({
  userId: userIdSchema.optional(),
  user_id: userIdSchema.optional(),
})
  .or('userId', 'user_id')
  .required();

export const createDeletionRequestSchema = Joi.object({
  userId: userIdSchema.optional(),
  user_id: userIdSchema.optional(),
  operationId: Joi.string().uuid().optional(),
  operation_id: Joi.string().uuid().optional(),
})
  .or('userId', 'user_id')
  .or('operationId', 'operation_id')
  .required();

export const getDeletionRequestSchema = Joi.object({
  deletionRequestId: Joi.string().uuid().required(),
}).required();

export const advanceDeletionRequestSchema = Joi.object({
  newStatus: Joi.string().valid(
    'SHRED_REQUESTED',
    'KEY_DESTROYED',
    'CASCADE_PENDING',
    'CASCADE_IN_PROGRESS',
    'CASCADE_COMPLETE',
    'CASCADE_PARTIAL_FAILURE',
    'CERTIFICATE_ISSUED'
  ).optional(),
  new_status: Joi.string().valid(
    'SHRED_REQUESTED',
    'KEY_DESTROYED',
    'CASCADE_PENDING',
    'CASCADE_IN_PROGRESS',
    'CASCADE_COMPLETE',
    'CASCADE_PARTIAL_FAILURE',
    'CERTIFICATE_ISSUED'
  ).optional(),
  operationId: Joi.string().uuid().optional(),
  operation_id: Joi.string().uuid().optional(),
})
  .or('newStatus', 'new_status')
  .or('operationId', 'operation_id')
  .required();

export const createAnalystClaimsSchema = Joi.object({
  analystEmails: Joi.array().items(Joi.string().email()).min(1).max(50).required(),
}).required();

// Base64url, matching randomBytes(32).toString('base64url') -- no padding,
// URL-safe alphabet only.
const claimTokenSchema = Joi.string()
  .pattern(/^[A-Za-z0-9_-]+$/)
  .min(20)
  .max(128)
  .required()
  .messages({
    'string.pattern.base': 'token must be a valid base64url string',
  });

export const claimAnalystTokenSchema = Joi.object({
  token: claimTokenSchema,
}).required();

export async function validateRequest(schema: Joi.ObjectSchema, payload: unknown): Promise<any> {
  const { error, value } = schema.validate(payload, {
    abortEarly: false,
    stripUnknown: true,
  });

  if (error) {
    const messages = error.details.map((detail) => ({
      field: detail.path.join('.'),
      message: detail.message,
    }));
    throw {
      statusCode: 400,
      message: 'Validation failed',
      errors: messages,
    };
  }

  return value;
}
