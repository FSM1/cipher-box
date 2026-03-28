/**
 * Structured logger for the CipherBox web application.
 *
 * Replaces raw console.* calls with level-filtered, tagged output.
 * In production (import.meta.env.PROD), only warn and error are emitted.
 * In development, all levels are emitted.
 *
 * Usage:
 *   import { logger } from '../lib/logger';
 *   logger.info('[Auth] User logged in');
 *   logger.warn('[IPFS] Unpin failed', err);
 *   logger.error('[Bin] Restore failed', err);
 *   logger.debug('[CoreKit] exportTssKey starting...');
 */

export enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3,
  SILENT = 4,
}

const LOG_LEVEL_LABELS: Record<LogLevel, string> = {
  [LogLevel.DEBUG]: 'DEBUG',
  [LogLevel.INFO]: 'INFO',
  [LogLevel.WARN]: 'WARN',
  [LogLevel.ERROR]: 'ERROR',
  [LogLevel.SILENT]: '',
};

/** Minimum log level. Evaluated once at module load for zero overhead. */
const minLevel: LogLevel = import.meta.env.PROD ? LogLevel.WARN : LogLevel.DEBUG;

function shouldLog(level: LogLevel): boolean {
  return level >= minLevel;
}

function formatMessage(level: LogLevel, args: unknown[]): unknown[] {
  const label = LOG_LEVEL_LABELS[level];
  const timestamp = new Date().toISOString();
  return [`[${timestamp}] ${label}:`, ...args];
}

export const logger = {
  get level(): LogLevel {
    return minLevel;
  },

  debug(...args: unknown[]): void {
    if (shouldLog(LogLevel.DEBUG)) {
      console.debug(...formatMessage(LogLevel.DEBUG, args));
    }
  },

  info(...args: unknown[]): void {
    if (shouldLog(LogLevel.INFO)) {
      console.info(...formatMessage(LogLevel.INFO, args));
    }
  },

  warn(...args: unknown[]): void {
    if (shouldLog(LogLevel.WARN)) {
      console.warn(...formatMessage(LogLevel.WARN, args));
    }
  },

  error(...args: unknown[]): void {
    if (shouldLog(LogLevel.ERROR)) {
      console.error(...formatMessage(LogLevel.ERROR, args));
    }
  },
};

export type Logger = typeof logger;
