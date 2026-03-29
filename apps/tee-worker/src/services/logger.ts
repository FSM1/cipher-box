/**
 * Minimal structured JSON logger for TEE worker.
 *
 * No external dependencies -- outputs newline-delimited JSON to stdout/stderr.
 * Compatible with Grafana Loki, CloudWatch, and other log aggregators.
 *
 * SECURITY: Never log key material, encrypted keys, auth tokens,
 * or IPNS private keys. Only log operation metadata (counts, timings,
 * error messages).
 */

type LogLevel = 'info' | 'warn' | 'error';

function log(level: LogLevel, message: string, data?: Record<string, unknown>): void {
  const entry = {
    timestamp: new Date().toISOString(),
    level,
    service: 'tee-worker',
    message,
    ...data,
  };
  const output = JSON.stringify(entry);
  if (level === 'error') {
    process.stderr.write(output + '\n');
  } else {
    process.stdout.write(output + '\n');
  }
}

export const logger = {
  info: (message: string, data?: Record<string, unknown>) => log('info', message, data),
  warn: (message: string, data?: Record<string, unknown>) => log('warn', message, data),
  error: (message: string, data?: Record<string, unknown>) => log('error', message, data),
};
