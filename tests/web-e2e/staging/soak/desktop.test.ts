import { describe, expect, it } from 'vitest';
import {
  appendDesktopMarker,
  desktopMarkerBytes,
  desktopMarkers,
  osMarkersLine,
  type DesktopMarker,
} from './desktop';
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

describe('the desktop marker lines', () => {
  it('read back beside an owner marker line', () => {
    let ledger = appendMarker(emptyLedger(), { date: '2026-09-29', ipnsName: NAME, sequence: 1 });
    ledger = appendDesktopMarker(ledger, { origin: 'linux', date: '2026-09-30' });
    ledger = appendDesktopMarker(ledger, { origin: 'web', date: '2026-09-30' });
    const read = parseLedger(formatLedger(ledger));
    expect(desktopMarkers(read)).toEqual([
      { origin: 'linux', date: '2026-09-30' },
      { origin: 'web', date: '2026-09-30' },
    ]);
    expect(markers(read)).toHaveLength(1);
    expect(formatLedger(read)).toContain('\nmarker linux 2026-09-30\n');
  });

  it('are appended once per origin and day', () => {
    const once = appendDesktopMarker(emptyLedger(), { origin: 'web', date: '2026-09-30' });
    expect(appendDesktopMarker(once, { origin: 'web', date: '2026-09-30' })).toBe(once);
  });

  it.each([
    ['an unknown origin', 'marker android 2026-09-30'],
    ['a bad day', 'marker macos 2026-02-30'],
    ['an extra field', 'marker macos 2026-09-30 x'],
    ['no day', 'marker macos'],
  ])('refuse %s as ledger-unparsable', (_label, line) => {
    const ledger = parseLedger(`${LEDGER_HEADER}\n${line}\n`);
    expect(reasonOf(() => desktopMarkers(ledger))).toBe('ledger-unparsable');
  });

  it('refuse to append a marker they would misread', () => {
    const marker = { origin: 'web', date: '2026-9-30' } as DesktopMarker;
    expect(reasonOf(() => appendDesktopMarker(emptyLedger(), marker))).toBe('ledger-unparsable');
  });
});

describe('the desktop marker bytes', () => {
  it('differ by origin and by day', () => {
    const text = (marker: DesktopMarker) => new TextDecoder().decode(desktopMarkerBytes(marker));
    expect(text({ origin: 'macos', date: '2026-09-30' })).toBe(
      'cipherbox soak marker macos 2026-09-30\n'
    );
    expect(text({ origin: 'web', date: '2026-09-30' })).not.toBe(
      text({ origin: 'windows', date: '2026-09-30' })
    );
  });
});

describe('the OS summary line', () => {
  it('names each OS leg, with a leg that wrote nothing as none', () => {
    expect(
      osMarkersLine([
        { origin: 'macos', date: '2026-09-29' },
        { origin: 'macos', date: '2026-09-30' },
        { origin: 'windows', date: '2026-09-28' },
        { origin: 'web', date: '2026-09-30' },
      ])
    ).toBe('macos 2, newest 2026-09-30; linux none; windows 1, newest 2026-09-28');
  });
});
