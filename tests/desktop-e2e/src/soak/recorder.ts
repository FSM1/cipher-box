/**
 * The results of one desktop leg, in the web soak's record shape, so one
 * summary renders the web run and every leg. The summary is public: a detail is
 * one short line of assertion text and never carries a key or a token.
 */

import { SoakFailure, type FailureReason } from '../../../web-e2e/staging/soak/reasons';
import { encodeRecord, shortDetail, type SoakRecord } from '../../../web-e2e/staging/soak/summary';

/** Takes one encoded results line. */
export type Sink = (line: string) => Promise<void>;

export class Recorder {
  readonly records: SoakRecord[] = [];
  private readonly thrown = new WeakSet<object>();

  constructor(private readonly sink: Sink) {}

  get failures(): number {
    return this.records.filter((entry) => entry.kind === 'check' && entry.outcome === 'failed')
      .length;
  }

  /**
   * Runs one check and records its outcome. A failure carries `reason` unless
   * the body threw a {@link SoakFailure} that names its own.
   */
  async check<T>(name: string, reason: FailureReason, body: () => Promise<T>): Promise<T> {
    let value: T;
    try {
      value = await body();
    } catch (error) {
      const failure =
        error instanceof SoakFailure
          ? error
          : new SoakFailure(reason, error instanceof Error ? error.message : String(error), {
              cause: error,
            });
      await this.add({
        kind: 'check',
        check: name,
        outcome: 'failed',
        reason: failure.reason,
        detail: shortDetail(failure.detail),
      });
      this.thrown.add(failure);
      throw failure;
    }
    await this.add({ kind: 'check', check: name, outcome: 'passed' });
    return value;
  }

  /** Whether `error` is the failure a check already recorded. */
  recorded(error: unknown): boolean {
    return typeof error === 'object' && error !== null && this.thrown.has(error);
  }

  fact(label: string, value: string): Promise<void> {
    return this.add({ kind: 'fact', label, value: shortDetail(value) });
  }

  phase(test: string, phase: 'started' | 'ended'): Promise<void> {
    return this.add({ kind: 'test', test, phase });
  }

  /** The failed line for an error that ended the leg outside every check. */
  unrecorded(test: string, error: unknown): Promise<void> {
    return this.add({
      kind: 'check',
      check: test,
      outcome: 'failed',
      reason: 'unrecorded-failure',
      detail: shortDetail(error instanceof Error ? error.message : String(error)),
    });
  }

  private async add(entry: SoakRecord): Promise<void> {
    const line = encodeRecord(entry);
    this.records.push(entry);
    await this.sink(line);
  }
}
