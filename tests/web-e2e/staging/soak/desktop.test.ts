import { describe, expect, it } from 'vitest';
import { legMarkers, markerDate, markersToRead, readLine, recordMarker } from './desktop';
import {
  appendMarker,
  emptyLedger,
  formatLedger,
  LEDGER_HEADER,
  markers,
  parseLedger,
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

describe('the leg marker lines', () => {
  it('read back beside an owner marker line', () => {
    let ledger = appendMarker(emptyLedger(), { date: '2026-09-29', ipnsName: NAME, sequence: 1 });
    ledger = recordMarker(ledger, { leg: 'linux', date: '2026-09-30' });
    ledger = recordMarker(ledger, { leg: 'web', date: '2026-09-30' });
    const read = parseLedger(formatLedger(ledger));
    expect(legMarkers(read)).toEqual([
      { leg: 'linux', date: '2026-09-30' },
      { leg: 'web', date: '2026-09-30' },
    ]);
    expect(markers(read)).toHaveLength(1);
    expect(formatLedger(read)).toContain('\nmarker web 2026-09-30\n');
  });

  it('are recorded once per leg and day', () => {
    const once = recordMarker(emptyLedger(), { leg: 'web', date: '2026-09-30' });
    expect(recordMarker(once, { leg: 'web', date: '2026-09-30' })).toBe(once);
  });

  it.each([
    ['an unknown leg', 'marker android 2026-09-30'],
    ['a bad day', 'marker macos 2026-02-30'],
    ['an extra field', 'marker macos 2026-09-30 x'],
    ['no day', 'marker macos'],
  ])('refuse %s as ledger-unparsable', (_label, line) => {
    const ledger = parseLedger(`${LEDGER_HEADER}\n${line}\n`);
    expect(reasonOf(() => legMarkers(ledger))).toBe('ledger-unparsable');
  });

  it('refuse to record a marker they would misread', () => {
    expect(reasonOf(() => recordMarker(emptyLedger(), { leg: 'web', date: '2026-9-30' }))).toBe(
      'ledger-unparsable'
    );
  });
});

describe('the markers the browser leg reads', () => {
  it('take the OS markers from the ledger and the listings, and skip its own', () => {
    let ledger = recordMarker(emptyLedger(), { leg: 'macos', date: '2026-09-29' });
    ledger = recordMarker(ledger, { leg: 'web', date: '2026-09-29' });
    const read = markersToRead(
      ledger,
      {
        macos: ['marker-2026-09-29.txt', 'marker-2026-09-30.txt'],
        windows: ['marker-2026-09-30.txt', 'notes.txt'],
        web: ['marker-2026-09-30.txt'],
      },
      'web'
    );
    expect(read).toEqual([
      { leg: 'macos', date: '2026-09-29' },
      { leg: 'macos', date: '2026-09-30' },
      { leg: 'windows', date: '2026-09-30' },
    ]);
    expect(readLine(read)).toBe('macos 2, windows 1');
    expect(readLine([])).toBe('no marker of another leg yet');
  });

  it('name a marker file by its day only', () => {
    expect(markerDate('marker-2026-09-30.txt')).toBe('2026-09-30');
    expect(markerDate('marker-2026-02-30.txt')).toBeNull();
    expect(markerDate('marker-2026-09-30 (1).txt')).toBeNull();
  });
});
