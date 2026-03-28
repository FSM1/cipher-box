import {
  initializeFaro,
  getWebInstrumentations,
  type Faro,
  type TransportItem,
  LogLevel,
} from '@grafana/faro-web-sdk';
import { TracingInstrumentation } from '@grafana/faro-web-tracing';
import { ReactIntegration } from '@grafana/faro-react';

/** Field names containing crypto material or PII — scrubbed from all Faro payloads. */
const SENSITIVE_KEYS = new Set([
  'privateKey',
  'rootFolderKey',
  'folderKey',
  'fileKey',
  'accessToken',
  'ipnsPrivateKey',
  'teePublicKey',
  'userEmail',
  'email',
]);

/** 64+ hex chars = 32+ byte key material */
const HEX_KEY_PATTERN = /^[0-9a-fA-F]{64,}$/;

/** Matches hex key material embedded in URLs (invite links, hash fragments) */
const URL_HEX_KEY_PATTERN = /[0-9a-fA-F]{64,}/g;

function scrubValue(value: unknown): unknown {
  if (typeof value === 'string') {
    if (value.length >= 64 && HEX_KEY_PATTERN.test(value)) {
      return '[REDACTED_KEY]';
    }
    // Scrub hex keys embedded in URLs (e.g., invite links with key material in hash/query)
    if (value.length > 64 && URL_HEX_KEY_PATTERN.test(value)) {
      URL_HEX_KEY_PATTERN.lastIndex = 0; // Reset regex state after test()
      return value.replace(URL_HEX_KEY_PATTERN, '[REDACTED_KEY]');
    }
  }
  if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) {
    return '[REDACTED_BINARY]';
  }
  if (typeof value === 'object' && value !== null && 'buffer' in value && 'byteLength' in value) {
    return '[REDACTED_BINARY]';
  }
  return value;
}

/** Recursively scrub sensitive keys/values. Beyond max depth, redacts rather than leaks. */
function scrubObject(obj: Record<string, unknown>, depth = 0): Record<string, unknown> {
  if (depth > 3) return { _redacted: '[DEPTH_LIMIT]' };

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

    if (Array.isArray(value)) {
      result[key] = value.map((item) => {
        const s = scrubValue(item);
        if (s !== item) return s;
        if (typeof item === 'object' && item !== null) {
          return scrubObject(item as Record<string, unknown>, depth + 1);
        }
        return item;
      });
    } else if (typeof value === 'object' && value !== null) {
      result[key] = scrubObject(value as Record<string, unknown>, depth + 1);
    } else {
      result[key] = value;
    }
  }
  return result;
}

/** Privacy gate: scrubs sensitive data before telemetry leaves the browser. */
function beforeSend(item: TransportItem): TransportItem | null {
  let modified = false;
  let payload = item.payload;
  let meta = item.meta;

  if (payload && typeof payload === 'object') {
    payload = scrubObject(
      payload as unknown as Record<string, unknown>
    ) as TransportItem['payload'];
    modified = true;
  }

  // Scrub meta (may contain nested sensitive values beyond just email)
  if (meta && typeof meta === 'object') {
    meta = scrubObject(meta as unknown as Record<string, unknown>) as TransportItem['meta'];
    modified = true;
  }

  return modified ? { ...item, payload, meta } : item;
}

let faroInstance: Faro | undefined;

export function getFaroInstance(): Faro | undefined {
  return faroInstance;
}

/** Initialize Grafana Faro. No-op when VITE_FARO_URL is absent (local dev). */
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
        captureConsoleDisabledLevels: [],
      }),
      new TracingInstrumentation({
        instrumentationOptions: {
          // Prevent request/response bodies from reaching telemetry — may contain encrypted payloads
          fetchInstrumentationOptions: { ignoreNetworkEvents: true },
          xhrInstrumentationOptions: { ignoreNetworkEvents: true },
        },
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

/** Set current user identity on Faro (publicKey only, never email). */
export function setFaroUser(publicKey: string): void {
  const faro = getFaroInstance();
  if (!faro) return;
  faro.api.setUser({ id: publicKey });
}

/** Clear user identity from Faro (call on logout). */
export function clearFaroUser(): void {
  const faro = getFaroInstance();
  if (!faro) return;
  // Faro's setUser types don't accept null directly, but the SDK handles it correctly
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  faro.api.setUser(null as any);
}

/**
 * Register a Faro transport that forwards warn/error log calls to Grafana.
 * Integrates with Phase 28's logger transports array. No-op if Faro is not initialized.
 */
export function registerFaroTransport(
  loggerTransports: Array<
    (level: string, message: string, context?: Record<string, unknown>) => void
  >
): void {
  const faro = getFaroInstance();
  if (!faro) return;

  const toStringContext = (ctx: Record<string, unknown>): Record<string, string> => {
    // Scrub sensitive values before forwarding to Faro
    const scrubbed = scrubObject(ctx);
    return Object.fromEntries(
      Object.entries(scrubbed)
        .filter(([k]) => k !== 'error')
        .map(([k, v]) => [k, typeof v === 'string' ? v : String(v)])
    );
  };

  const faroTransport = (
    level: string,
    message: string,
    context?: Record<string, unknown>
  ): void => {
    if (level === 'error') {
      const error = context?.error instanceof Error ? context.error : new Error(message);
      faro.api.pushError(error, {
        context: context ? toStringContext(context) : undefined,
      });
    } else if (level === 'warn') {
      faro.api.pushLog([message], {
        level: LogLevel.WARN,
        context: context ? toStringContext(context) : undefined,
      });
    }
  };

  loggerTransports.push(faroTransport);
}
