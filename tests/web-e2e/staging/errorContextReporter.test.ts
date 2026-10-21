import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { TestCase, TestResult } from '@playwright/test/reporter';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import ErrorContextReporter, { ERROR_CONTEXT } from './errorContextReporter';

describe('the error-context reporter', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'error-context-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  const end = (attachments: TestResult['attachments']): TestResult['attachments'] => {
    const result = { attachments } as TestResult;
    new ErrorContextReporter().onTestEnd({} as TestCase, result);
    return result.attachments;
  };

  it('drops the error-context attachment and deletes its file', () => {
    const context = join(dir, 'error-context.md');
    writeFileSync(context, '# snapshot\n');

    const left = end([
      { name: ERROR_CONTEXT, contentType: 'text/markdown', path: context },
      { name: 'timings', contentType: 'application/json', body: Buffer.from('{}') },
    ]);

    expect(left.map(({ name }) => name)).toEqual(['timings']);
    expect(existsSync(context)).toBe(false);
  });

  it('keeps every other attachment and its file', () => {
    const screenshot = join(dir, 'shot.png');
    writeFileSync(screenshot, 'png');

    const left = end([
      { name: 'screenshot', contentType: 'image/png', path: screenshot },
      { name: 'stdout', contentType: 'text/plain', body: Buffer.from('ok') },
    ]);

    expect(left.map(({ name }) => name)).toEqual(['screenshot', 'stdout']);
    expect(existsSync(screenshot)).toBe(true);
  });

  it('drops an error-context attachment that carries a body and no file', () => {
    expect(
      end([{ name: ERROR_CONTEXT, contentType: 'text/markdown', body: Buffer.from('x') }])
    ).toEqual([]);
  });
});
