import { describe, expect, it } from 'vitest';
import { emptyLedger, formatLedger, LEDGER_HEADER, parseLedger } from './ledger';
import { SoakFailure } from './reasons';
import {
  cycleEpochStepped,
  grantsRead,
  linkPrefix,
  type DialogMark,
  type GrantsMarks,
  markerDates,
  parseEpochs,
  sharedEpochHeld,
  sharedLink,
  sharedOverCap,
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

describe('the shared folder cap', () => {
  it('moves the oldest days past the cap, and nothing under it', () => {
    const days = ['2026-09-28', '2026-09-29', '2026-09-30', '2026-10-01'];
    expect(sharedOverCap(days, 2)).toEqual(['2026-09-28', '2026-09-29']);
    expect(sharedOverCap(days, 4)).toEqual([]);
    expect(sharedOverCap(days, Infinity)).toEqual([]);
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

/** A dialog element that shows `text` from `from` ms after the fake opens until `until` ms. */
function mark(from: number, until = Infinity, text: string | null = ''): DialogMark {
  const opened = Date.now();
  const shown = () => {
    const at = Date.now() - opened;
    return at >= from && at < until;
  };
  return {
    isVisible: async () => shown(),
    textContent: async () => text,
    waitFor: ({ timeout }) =>
      new Promise((resolve, reject) => {
        const poll = setInterval(() => {
          if (shown()) {
            clearInterval(poll);
            resolve();
          } else if (Date.now() - opened > timeout) {
            clearInterval(poll);
            reject(Object.assign(new Error('timed out'), { name: 'TimeoutError' }));
          }
        }, 5);
      }),
  };
}

/** A dialog that keeps the unavailable note; fresh per call, as a mark times from its creation. */
function dialog(marks: Partial<GrantsMarks> = {}): GrantsMarks {
  return { people: mark(Infinity), unavailable: mark(0), error: mark(Infinity), ...marks };
}

describe('the cycle grants read', () => {
  it('waits out the unavailable note the dialog draws before its read lands', async () => {
    const marks = dialog({ people: mark(50), unavailable: mark(0, 50) });
    await expect(grantsRead(marks, 'cycle', 1_000)).resolves.toBeUndefined();
  });

  it('fails grants-unread with the budget where the unavailable note stays', async () => {
    await expect(grantsRead(dialog(), 'cycle', 100)).rejects.toStrictEqual(
      new SoakFailure(
        'grants-unread',
        'the share dialog of cycle/ showed the unavailable note in 0.1 s'
      )
    );
  });

  it('tells a dialog that drew neither the table nor the note', async () => {
    const marks = dialog({ unavailable: mark(Infinity) });
    await expect(grantsRead(marks, 'cycle', 100)).rejects.toStrictEqual(
      new SoakFailure('grants-unread', 'the share dialog of cycle/ showed no people table in 0.1 s')
    );
  });

  it('adds the refusal the dialog shows where its read threw', async () => {
    const marks = dialog({
      error: mark(0, Infinity, ' resolve failed: unavailable '),
    });
    await expect(grantsRead(marks, 'cycle', 100)).rejects.toStrictEqual(
      new SoakFailure(
        'grants-unread',
        'the share dialog of cycle/ showed the unavailable note in 0.1 s, refused: resolve failed: unavailable'
      )
    );
  });

  it('passes on an error that is not a timeout', async () => {
    const closed = new Error('Target page, context or browser has been closed');
    const marks = dialog({ people: { ...mark(Infinity), waitFor: () => Promise.reject(closed) } });
    await expect(grantsRead(marks, 'cycle', 100)).rejects.toBe(closed);
  });

  it('fails at once where the dialog shows a refusal', async () => {
    const marks = dialog({ error: mark(20, Infinity, 'resolve failed: unavailable') });
    const started = Date.now();
    await expect(grantsRead(marks, 'cycle', 60_000)).rejects.toStrictEqual(
      new SoakFailure(
        'grants-unread',
        'the share dialog of cycle/ showed the unavailable note in 60 s, refused: resolve failed: unavailable'
      )
    );
    expect(Date.now() - started).toBeLessThan(1_000);
  });

  it('omits the refusal where the error shows no text', async () => {
    const marks = dialog({ error: mark(0, Infinity, null) });
    await expect(grantsRead(marks, 'cycle', 100)).rejects.toStrictEqual(
      new SoakFailure(
        'grants-unread',
        'the share dialog of cycle/ showed the unavailable note in 0.1 s'
      )
    );
  });
});
