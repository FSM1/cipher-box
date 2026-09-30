import { describe, expect, it } from 'vitest';
import { emptyLedger, formatLedger, LEDGER_HEADER, parseLedger } from './ledger';
import { SoakFailure } from './reasons';
import {
  cycleEpochStepped,
  linkPrefix,
  markerDates,
  parseEpochs,
  sharedEpochHeld,
  sharedLink,
  withSharedLink,
} from './shares';

const LINK = new URL('https://app.example.test/invite#capability-bytes');

function reasonOf(act: () => unknown): string {
  try {
    act();
  } catch (error) {
    if (error instanceof SoakFailure) return error.reason;
    throw error;
  }
  throw new Error('expected a SoakFailure');
}

describe('the share dialog epochs', () => {
  it('reads the read and write epoch off the row', () => {
    expect(parseEpochs('// read epoch 3 · write epoch 1')).toEqual({ read: 3n, write: 1n });
    expect(parseEpochs('// read epoch 9007199254740993 · write epoch 2').read).toBe(
      9_007_199_254_740_993n
    );
  });

  it('refuses a row of another shape', () => {
    expect(() => parseEpochs('// read epoch ? · write epoch 1')).toThrow(/epoch row/);
  });
});

describe('the long-running link line', () => {
  it('is absent before the first mint', () => {
    expect(sharedLink(emptyLedger())).toBeNull();
  });

  it('round-trips through the ledger text', () => {
    const text = formatLedger(withSharedLink(emptyLedger(), { readEpoch: 1n, url: LINK }));
    const read = sharedLink(parseLedger(text));
    expect(read?.readEpoch).toBe(1n);
    expect(read?.url.href).toBe(LINK.href);
  });

  it.each([
    ['no fragment', 'shared-link 1 https://app.example.test/invite'],
    ['a bad epoch', 'shared-link -1 https://app.example.test/invite#x'],
    ['no URL', 'shared-link 1'],
    ['a non-web URL', 'shared-link 1 file:///invite#x'],
  ])('refuses a line with %s as ledger-unparsable', (_label, line) => {
    const ledger = parseLedger(`${LEDGER_HEADER}\n${line}\n`);
    expect(reasonOf(() => sharedLink(ledger))).toBe('ledger-unparsable');
  });

  it('refuses to write a URL that carries no capability', () => {
    const url = new URL('https://app.example.test/invite');
    expect(reasonOf(() => withSharedLink(emptyLedger(), { readEpoch: 1n, url }))).toBe(
      'ledger-unparsable'
    );
  });

  it('shows no byte of the capability in its prefix', () => {
    expect(linkPrefix(LINK)).toBe('https://app.example.test/invite#...');
    expect(linkPrefix(LINK)).not.toContain('capability');
  });
});

describe('the epoch assertions', () => {
  it('hold the long-running link at its recorded epoch', () => {
    expect(() => sharedEpochHeld(2n, 2n)).not.toThrow();
    expect(reasonOf(() => sharedEpochHeld(2n, 3n))).toBe('shared-epoch-stepped');
  });

  it('want a cycle revoke to step the read epoch by exactly one', () => {
    expect(() => cycleEpochStepped(4n, 5n)).not.toThrow();
    expect(reasonOf(() => cycleEpochStepped(4n, 4n))).toBe('cycle-epoch-flat');
    expect(reasonOf(() => cycleEpochStepped(4n, 6n))).toBe('cycle-epoch-flat');
  });
});

describe('the marker files of a listing', () => {
  it('names the days of the markers only, oldest first', () => {
    expect(
      markerDates([
        'marker-2026-10-02.txt',
        'notes.txt',
        'marker-2026-09-30.txt',
        'marker-2026-10-01 (1).txt',
      ])
    ).toEqual(['2026-09-30', '2026-10-02']);
  });
});
