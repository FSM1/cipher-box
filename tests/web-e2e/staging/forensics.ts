/**
 * What a failed staging spec leaves in its public report: refused and failed
 * requests, console errors and alert text. A trace stays off, since it records
 * the session bearer and the accelerator pseudonym; this log reads no header
 * and no body, and redacts each line.
 */

import type { Page } from '@playwright/test';

// The shapes of a token, a key, a share or a person: a JWT, a query or a
// fragment, an email, padded base64, and a long run inside one path segment, so
// that the path around it stays readable.
const SECRET_SHAPES: readonly RegExp[] = [
  /eyJ[\w-]*\.[\w-]*\.[\w-]*/g,
  /[?#][^\s"']*/g,
  /[\w.+-]+@[\w-]+(?:\.[\w-]+)+/g,
  /[A-Za-z0-9+/]{24,}={1,2}/g,
  /[A-Za-z0-9+_-]{24,}/g,
];

export function redact(text: string): string {
  return SECRET_SHAPES.reduce((line, shape) => line.replace(shape, '[redacted]'), text);
}

/** The host and the path of `url`; the query can carry a token. */
export function requestTarget(url: string): string {
  try {
    const parsed = new URL(url);
    return `${parsed.host}${parsed.pathname}`;
  } catch {
    return 'an unparsable url';
  }
}

export interface Forensics {
  /** The log so far, plus the alert text the page shows now. */
  report(): Promise<string>;
}

export function recordForensics(page: Page): Forensics {
  const started = Date.now();
  const lines: string[] = [];
  const note = (line: string): void => {
    const seconds = ((Date.now() - started) / 1000).toFixed(1);
    lines.push(redact(`+${seconds}s ${line}`));
  };

  page.on('response', (response) => {
    if (response.status() >= 400) {
      note(`response ${response.status()} ${requestTarget(response.url())}`);
    }
  });
  page.on('requestfailed', (request) => {
    note(`failed ${requestTarget(request.url())}: ${request.failure()?.errorText ?? 'unknown'}`);
  });
  page.on('console', (message) => {
    if (message.type() === 'error') note(`console ${message.text()}`);
  });
  page.on('pageerror', (error) => note(`page error ${error.message}`));

  return {
    async report() {
      const alerts = page.isClosed()
        ? []
        : await page
            .getByRole('alert')
            .allInnerTexts()
            .catch(() => []);
      return [...lines, ...alerts.map((alert) => redact(`alert ${alert.trim()}`))].join('\n');
    },
  };
}
