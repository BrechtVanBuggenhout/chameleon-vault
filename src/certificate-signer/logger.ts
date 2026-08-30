import { pino, type Logger as PinoLogger } from 'pino';

// A local, minimal logger -- deliberately NOT a reuse of ../logging/index.js,
// which transitively pulls in @google-cloud/logging (for Cloud Logging
// export at warn/error levels) via ../logging/cloud-logging.ts. That's a
// real, unnecessary 4th dependency for this module: sign.ts's only log call
// is a plain operational info line, not a CHAIN_ANCHOR_MARKER-tagged audit
// event (those are all logged by certificate-service.ts, the orchestrator,
// which keeps its own full Cloud Logging access unaffected by this). Plain
// stdout JSON logging is also the right choice for a workload that will
// eventually run inside a Confidential Space enclave, where structured
// stdout is the normal way logs leave the environment anyway.
const pinoLogger = pino({ level: process.env.LOG_LEVEL || 'info' });

export type Logger = PinoLogger;

export function createLogger(module: string): PinoLogger {
  return pinoLogger.child({ module });
}
