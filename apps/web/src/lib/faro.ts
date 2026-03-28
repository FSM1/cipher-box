import {
  initializeFaro,
  getWebInstrumentations,
  type Faro,
  type TransportItem,
  LogLevel,
} from '@grafana/faro-web-sdk';
import { ReactIntegration } from '@grafana/faro-react';

/**
 * Sensitive field names that must be scrubbed from all Faro payloads.
 * Matches the CipherBox terminology standards from CLAUDE.md.
 */
const SENSITIVE_KEYS = new Set([
  'privateKey',
  'rootFolderKey',
  'folderKey',
  'fileKey',
  'accessToken',
  'ipnsPrivateKey',
  'teePublicKey',
  'userEmail',
]);

/**
 * Detects hex-encoded cryptographic keys (64+ hex chars = 32+ bytes).
 */
const HEX_KEY_PATTERN = /^[0-9a-fA-F]{64,}$/;

/**
 * Scrub a single value: redact hex keys and binary data.
 */
function scrubValue(value: unknown): unknown {
  if (typeof value === 'string' && HEX_KEY_PATTERN.test(value)) {
    return '[REDACTED_KEY]';
  }
  if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) {
    return '[REDACTED_BINARY]';
  }
  if (typeof value === 'object' && value !== null && 'buffer' in value && 'byteLength' in value) {
    return '[REDACTED_BINARY]';
  }
  return value;
}

/**
 * Recursively scrub an object: redact sensitive keys and values.
 * Limited to 3 levels of depth to prevent infinite recursion.
 */
function scrubObject(obj: Record<string, unknown>, depth = 0): Record<string, unknown> {
  if (depth > 3) return obj;

  const result: Record<string, unknown> = {};
  for (const key of Object.keys(obj)) {
    const value = obj[key];

    if (SENSITIVE_KEYS.has(key)) {
      result[key] = '[REDACTED]';
      continue;
    }

    const scrubbed = scrubValue(value);
    if (scrubbed !== value) {
      result[key] = scrubbed;
      continue;
    }

    if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      result[key] = scrubObject(value as Record<string, unknown>, depth + 1);
    } else {
      result[key] = value;
    }
  }
  return result;
}

/**
 * Privacy gate: scrubs all sensitive data from Faro transport items
 * before they leave the browser.
 */
function beforeSend(item: TransportItem): TransportItem | null {
  // Deep-scrub payload
  if (item.payload && typeof item.payload === 'object') {
    item = {
      ...item,
      payload: scrubObject(
        item.payload as unknown as Record<string, unknown>
      ) as TransportItem['payload'],
    };
  }

  // Strip email from user meta — only publicKey (as id) is allowed
  if (item.meta?.user?.email) {
    item = {
      ...item,
      meta: {
        ...item.meta,
        user: {
          ...item.meta.user,
          email: undefined,
        },
      },
    };
  }

  return item;
}

let faroInstance: Faro | undefined;

/**
 * Returns the Faro instance, or undefined if not initialized.
 */
export function getFaroInstance(): Faro | undefined {
  return faroInstance;
}

/**
 * Initialize Grafana Faro observability SDK.
 * No-op when VITE_FARO_URL is absent (local dev).
 */
export function initFaro(): Faro | undefined {
  const faroUrl = import.meta.env.VITE_FARO_URL;
  if (!faroUrl) return undefined;

  faroInstance = initializeFaro({
    url: faroUrl,
    app: {
      name: 'cipherbox-web',
      version: import.meta.env.VITE_APP_VERSION ?? 'dev',
      environment: import.meta.env.VITE_ENVIRONMENT ?? 'development',
    },
    instrumentations: [
      ...getWebInstrumentations({
        captureConsole: false, // Phase 28 logger handles console capture
      }),
      new ReactIntegration(),
    ],
    beforeSend,
    sessionTracking: {
      enabled: true,
      persistent: false, // Don't persist session across tabs
    },
  });

  return faroInstance;
}

/**
 * Set the current user identity on Faro (publicKey only, never email).
 */
export function setFaroUser(publicKey: string): void {
  const faro = getFaroInstance();
  if (!faro) return;
  faro.api.setUser({ id: publicKey });
}

/**
 * Clear the current user identity from Faro (call on logout).
 */
export function clearFaroUser(): void {
  const faro = getFaroInstance();
  if (!faro) return;
  faro.api.setUser(null as unknown as Parameters<typeof faro.api.setUser>[0]);
}

/**
 * Register a Faro transport that forwards warn/error log calls to Grafana.
 * Designed to integrate with Phase 28's logger transports array.
 * No-op if Faro is not initialized.
 *
 * @param loggerTransports - The transports array from the logger module.
 *   Each transport is called as (level, message, context?) for every log call.
 */
export function registerFaroTransport(
  loggerTransports: Array<
    (level: string, message: string, context?: Record<string, unknown>) => void
  >
): void {
  const faro = getFaroInstance();
  if (!faro) return;

  const faroTransport = (
    level: string,
    message: string,
    context?: Record<string, unknown>
  ): void => {
    if (level === 'error') {
      const error = context?.error instanceof Error ? context.error : new Error(message);
      faro.api.pushError(error, {
        context: context
          ? Object.fromEntries(
              Object.entries(context)
                .filter(([k]) => k !== 'error')
                .map(([k, v]) => [k, String(v)])
            )
          : undefined,
      });
    } else if (level === 'warn') {
      faro.api.pushLog([message], {
        level: LogLevel.WARN,
        context: context
          ? Object.fromEntries(Object.entries(context).map(([k, v]) => [k, String(v)]))
          : undefined,
      });
    }
    // debug and info are not forwarded — noise reduction
  };

  loggerTransports.push(faroTransport);
}
