import { Logging, Log } from '@google-cloud/logging';
import { getRequiredEnv } from '../config/env.js';

let cloudLoggingClient: Logging | null = null;

export function initializeCloudLogging(): Logging {
  if (!cloudLoggingClient) {
    const projectId = process.env.LOG_PROJECT_ID || getRequiredEnv('GCP_PROJECT_ID', 'test-project');
    cloudLoggingClient = new Logging({
      projectId,
    });
  }
  return cloudLoggingClient;
}

export function getCloudLogger(logName: string): Log {
  const logging = initializeCloudLogging();
  return logging.log(logName);
}

export interface CloudLogEntry {
  severity: 'DEFAULT' | 'DEBUG' | 'INFO' | 'NOTICE' | 'WARNING' | 'ERROR' | 'CRITICAL' | 'ALERT' | 'EMERGENCY';
  message: string;
  labels?: Record<string, string>;
  data?: Record<string, unknown>;
  timestamp?: Date;
  sourceLocation?: {
    file: string;
    line: number;
    function: string;
  };
}

export async function writeLog(logEntry: CloudLogEntry, logName: string = 'chameleon-key-vault'): Promise<void> {
  if (process.env.NODE_ENV !== 'production') {
    return;
  }

  try {
    const logger = getCloudLogger(logName);
    const entry = logger.entry(
      {
        severity: logEntry.severity,
        labels: logEntry.labels,
        sourceLocation: logEntry.sourceLocation,
      },
      {
        message: logEntry.message,
        ...logEntry.data,
      }
    );

    await logger.write(entry);
  } catch (error) {
    console.error('Failed to write to Cloud Logging:', error);
  }
}

export function mapPinoLevelToCloudSeverity(level: number): CloudLogEntry['severity'] {
  const severityMap: Record<number, CloudLogEntry['severity']> = {
    10: 'DEBUG',
    20: 'DEBUG',
    30: 'INFO',
    40: 'WARNING',
    50: 'ERROR',
    60: 'CRITICAL',
  };
  return severityMap[level] || 'DEFAULT';
}
