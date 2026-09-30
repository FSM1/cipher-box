import { describe, expect, it } from 'vitest';
import {
  ledgerLine,
  ledgerPath,
  legMarkers,
  markerDate,
  markerPath,
  markersToRead,
  READ_WINDOW,
  readLine,
  recordMarker,
} from './grantee';
import { emptyLedger, formatLedger, parseLedger, type Ledger } from './ledger';
import { SoakFailure } from './reasons';

function ledgerOf(...lines: string[]): Ledger {
  return parseLedger(['cipherbox-soak-ledger 1', ...lines].join('\n') + '\n');
}

describe('the marker paths', () => {
  it('put a marker in the folder of its leg, under the grantee ledger folder', () => {
    expect(markerPath({ leg: 'linux', date: '2026-09-30' })).toEqual([
      'soak',
      'desktop',
      'linux',
      'marker-2026-09-30.txt',
    ]);
    expect(ledgerPath()).toEqual(['soak', 'desktop', 'ledger.txt']);
  });

  it('read a marker day back from its file name only', () => {
    expect(markerDate('marker-2026-09-30.txt')).toBe('2026-09-30');
    expect(markerDate('marker-2026-02-30.txt')).toBeNull();
    expect(markerDate('marker-2026-09-30.txt.tmp')).toBeNull();
    expect(markerDate('ledger.txt')).toBeNull();
  });
});

describe('the grantee ledger lines', () => {
  it('survive a write and a read through the web ledger format', () => {
    const written = recordMarker(emptyLedger(), { leg: 'windows', date: '2026-09-30' });
    const text = formatLedger(written);
    expect(text).toBe('cipherbox-soak-ledger 1\nmarker windows 2026-09-30\n');
    expect(legMarkers(parseLedger(text))).toEqual([{ leg: 'windows', date: '2026-09-30' }]);
  });

  it('add the line of a day once, so a rerun leaves the ledger as it is', () => {
    const once = recordMarker(emptyLedger(), { leg: 'macos', date: '2026-09-30' });
    expect(recordMarker(once, { leg: 'macos', date: '2026-09-30' })).toBe(once);
    expect(recordMarker(once, { leg: 'linux', date: '2026-09-30' }).lines).toHaveLength(2);
  });

  it('carry every line of another shape through a rewrite', () => {
    const ledger = ledgerOf('2026-09-29 k51abc 3', 'binned 2026-06-01 2026-09-01');
    const next = recordMarker(ledger, { leg: 'macos', date: '2026-09-30' });
    expect(formatLedger(next)).toBe(
      'cipherbox-soak-ledger 1\n2026-09-29 k51abc 3\nbinned 2026-06-01 2026-09-01\n' +
        'marker macos 2026-09-30\n'
    );
  });

  it('refuse a marker line of a leg or a day this soak does not know', () => {
    for (const line of ['marker android 2026-09-30', 'marker macos 2026-13-01', 'marker macos']) {
      expect(() => legMarkers(ledgerOf(line))).toThrow(
        expect.objectContaining({ name: 'SoakFailure', reason: 'ledger-unparsable' })
      );
    }
    expect(() => ledgerLine({ leg: 'macos', date: '2026-9-30' })).toThrow(SoakFailure);
  });
});

describe('the markers a leg reads', () => {
  it('take the other legs from the ledger and the listings both, and skip its own', () => {
    const ledger = ledgerOf(
      'marker linux 2026-09-28',
      'marker macos 2026-09-28',
      'marker windows 2026-09-29'
    );
    const read = markersToRead(
      ledger,
      {
        linux: ['marker-2026-09-28.txt', 'marker-2026-09-29.txt', 'notes.txt'],
        macos: ['marker-2026-09-29.txt'],
        web: ['marker-2026-09-29.txt'],
      },
      'macos'
    );
    expect(read).toEqual([
      { leg: 'linux', date: '2026-09-28' },
      { leg: 'linux', date: '2026-09-29' },
      { leg: 'windows', date: '2026-09-29' },
      { leg: 'web', date: '2026-09-29' },
    ]);
    expect(readLine(read)).toBe('linux 2, windows 1, web 1');
  });

  it('lets the web leg read every desktop leg', () => {
    const ledger = ledgerOf('marker web 2026-09-28', 'marker linux 2026-09-28');
    expect(markersToRead(ledger, { windows: ['marker-2026-09-29.txt'] }, 'web')).toEqual([
      { leg: 'linux', date: '2026-09-28' },
      { leg: 'windows', date: '2026-09-29' },
    ]);
  });

  it('reads only the newest markers of each leg', () => {
    const days = Array.from({ length: READ_WINDOW + 3 }, (_, index) =>
      new Date(Date.UTC(2026, 8, 1 + index)).toISOString().slice(0, 10)
    );
    const listed = days.map((day) => `marker-${day}.txt`);
    const read = markersToRead(
      ledgerOf('marker web 2026-09-01'),
      { linux: listed, windows: listed.slice(0, 2) },
      'macos'
    );
    expect(read.filter((marker) => marker.leg === 'linux').map((m) => m.date)).toEqual(
      days.slice(-READ_WINDOW)
    );
    expect(read.filter((marker) => marker.leg === 'windows')).toHaveLength(2);
    expect(read.filter((marker) => marker.leg === 'web')).toHaveLength(1);
  });

  it('is none on the first night', () => {
    expect(markersToRead(emptyLedger(), {}, 'linux')).toEqual([]);
    expect(readLine([])).toBe('no marker of another leg yet');
  });
});
