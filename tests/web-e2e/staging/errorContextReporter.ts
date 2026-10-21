/**
 * Drops the `error-context` attachment of each test, and its file. It holds an
 * ARIA snapshot of the page, which lists each link and field value on it, and a
 * staging report is a public artifact.
 */

import { rmSync } from 'node:fs';
import type { Reporter, TestCase, TestResult } from '@playwright/test/reporter';

export const ERROR_CONTEXT = 'error-context';

export default class ErrorContextReporter implements Reporter {
  // Every reporter gets the same result object, and the HTML reporter reads its
  // attachments in `onEnd`, so a removal here reaches the report.
  onTestEnd(_test: TestCase, result: TestResult): void {
    for (let index = result.attachments.length - 1; index >= 0; index -= 1) {
      const attachment = result.attachments[index];
      if (attachment.name !== ERROR_CONTEXT) continue;
      if (attachment.path !== undefined) rmSync(attachment.path, { force: true });
      result.attachments.splice(index, 1);
    }
  }
}
