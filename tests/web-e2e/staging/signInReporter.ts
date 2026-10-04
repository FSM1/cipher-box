/** Prints one line per staging run: the sign-ins, observed faults and retry stop reasons. */

import type { Reporter, TestCase, TestResult } from '@playwright/test/reporter';
import { SIGN_IN_ANNOTATION, summarize, type SignInRecord } from './loginRetry';

export default class SignInReporter implements Reporter {
  private readonly records: SignInRecord[] = [];

  onTestEnd(_test: TestCase, result: TestResult): void {
    for (const { type, description } of result.annotations) {
      if (type === SIGN_IN_ANNOTATION && description) {
        this.records.push(JSON.parse(description) as SignInRecord);
      }
    }
  }

  onEnd(): void {
    console.log(`[staging sign-in] ${summarize(this.records)}`);
  }
}
