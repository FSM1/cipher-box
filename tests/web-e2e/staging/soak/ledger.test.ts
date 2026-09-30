import { describe, expect, it } from 'vitest';
import {
  appendMarker,
  emptyLedger,
  formatLedger,
  isUtcDay,
  LEDGER_HEADER,
  markers,
  parseLedger,
  utcDay,
  type Ledger,
} from './ledger';
import { SoakFailure } from './reasons';

const NAME = 'k51qzi5uqu5dlvj2baxnqndepeb86cbk3ng7n3i46uzyxzyqj2xjonzllnv0v8';

function reasonOf(act: () => unknown): string {
  try {
    act();
  } catch (error) {
    if (error instanceof SoakFailure) return error.reason;
    throw error;
  }
  throw new Error('expected a SoakFailure');
}

describe('the soak ledger', () => {
  it('formats an empty ledger as the header alone', () => {
    expect(formatLedger(emptyLedger())).toBe(`${LEDGER_HEADER}\n`);
    expect(markers(parseLedger(`${LEDGER_HEADER}\n`))).toEqual([]);
  });

  it('round-trips markers and keeps a line of another shape in place', () => {
    const text = [
      LEDGER_HEADER,
      `2026-09-28 ${NAME} 1`,
      'shared-link https://app.example.test/s/abc read-epoch 3',
      '',
      `2026-09-29 ${NAME} 12`,
      '',
    ].join('\n');
    const ledger = parseLedger(text);
    expect(markers(ledger)).toEqual([
      { date: '2026-09-28', ipnsName: NAME, sequence: 1 },
      { date: '2026-09-29', ipnsName: NAME, sequence: 12 },
    ]);
    expect(formatLedger(ledger)).toBe(text);
  });

  it('reads a file saved with CRLF line ends', () => {
    const ledger = parseLedger(`${LEDGER_HEADER}\r\n2026-09-28 ${NAME} 4\r\n`);
    expect(markers(ledger)).toEqual([{ date: '2026-09-28', ipnsName: NAME, sequence: 4 }]);
  });

  it('appends a marker that reads back', () => {
    const ledger = appendMarker(emptyLedger(), { date: '2026-09-30', ipnsName: NAME, sequence: 7 });
    expect(markers(parseLedger(formatLedger(ledger)))).toEqual([
      { date: '2026-09-30', ipnsName: NAME, sequence: 7 },
    ]);
  });

  it.each([
    ['no header', `2026-09-28 ${NAME} 1\n`],
    ['a newer header', 'cipherbox-soak-ledger 2\n'],
    ['an empty file', ''],
    ['a missing sequence', `${LEDGER_HEADER}\n2026-09-28 ${NAME}\n`],
    ['a negative sequence', `${LEDGER_HEADER}\n2026-09-28 ${NAME} -1\n`],
    ['a leading-zero sequence', `${LEDGER_HEADER}\n2026-09-28 ${NAME} 01\n`],
    ['an unsafe sequence', `${LEDGER_HEADER}\n2026-09-28 ${NAME} 9007199254740993\n`],
    ['a day that does not exist', `${LEDGER_HEADER}\n2026-02-30 ${NAME} 1\n`],
    ['a name with a slash', `${LEDGER_HEADER}\n2026-09-28 ba/fy 1\n`],
    ['a doubled space', `${LEDGER_HEADER}\n2026-09-28  ${NAME} 1\n`],
  ])('refuses %s as ledger-unparsable', (_label, text) => {
    expect(reasonOf(() => parseLedger(text))).toBe('ledger-unparsable');
  });

  it.each([
    ['a bad day', { date: '2026-13-01', ipnsName: NAME, sequence: 1 }],
    ['a name with a space', { date: '2026-09-28', ipnsName: 'ba fy', sequence: 1 }],
    ['a fractional sequence', { date: '2026-09-28', ipnsName: NAME, sequence: 1.5 }],
    ['a negative sequence', { date: '2026-09-28', ipnsName: NAME, sequence: -1 }],
    ['an unsafe sequence', { date: '2026-09-28', ipnsName: NAME, sequence: 2 ** 53 }],
  ])('refuses to append %s', (_label, marker) => {
    expect(reasonOf(() => appendMarker(emptyLedger(), marker))).toBe('ledger-unparsable');
  });

  it('refuses to write a kept line that would read back as a marker', () => {
    const ledger: Ledger = { lines: [{ kind: 'other', text: `2026-09-28 ${NAME} 1 extra` }] };
    expect(reasonOf(() => formatLedger(ledger))).toBe('ledger-unparsable');
  });

  it('names UTC days', () => {
    expect(utcDay(new Date('2026-09-29T23:59:59Z'))).toBe('2026-09-29');
    expect(isUtcDay('2028-02-29')).toBe(true);
    expect(isUtcDay('2027-02-29')).toBe(false);
    expect(isUtcDay('2026-9-29')).toBe(false);
  });
});
