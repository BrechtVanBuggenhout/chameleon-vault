import { pino, type LogFn, type Logger as PinoLogger } from 'pino';
import { mapPinoLevelToCloudSeverity, writeLog } from './cloud-logging.js';

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

const pinoLogger = pino({
  level: process.env.LOG_LEVEL || 'info',
  transport:
    process.env.NODE_ENV === 'production'
      ? {
          target: 'pino/file',
          options: {
            destination: 1,
            mkdir: true,
          },
        }
      : {
          target: 'pino-pretty',
          options: {
            colorize: true,
            singleLine: false,
            ignore: 'pid,hostname',
          },
        },
  hooks: {
    logMethod(inputArgs: unknown[], method: LogFn, level: number) {
      const now = new Date();

      if (process.env.NODE_ENV === 'production' && level >= 30) {
        const [firstArg, ...restArgs] = inputArgs as unknown[];
        const logObject = isRecord(firstArg) ? firstArg : {};
        const message =
          restArgs.map(String).join(' ') ||
          (typeof logObject.msg === 'string' ? logObject.msg : undefined) ||
          (typeof firstArg === 'string' ? firstArg : undefined) ||
          'Log entry';
        const severity = mapPinoLevelToCloudSeverity(level);

        writeLog(
          {
            severity,
            message,
            data: logObject,
            timestamp: now,
          },
          'chameleon-key-vault'
        ).catch(() => {});
      }

      return method.apply(this, inputArgs as Parameters<LogFn>);
    },
  },
});

export type Logger = ReturnType<typeof createLogger>;

export function createLogger(module: string): PinoLogger {
  return pinoLogger.child({ module });
}

export default pinoLogger;
