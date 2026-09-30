import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  appendMarker,
  emptyLedger,
  formatLedger,
  markers,
  parseLedger,
  type Marker,
} from './ledger';
import {
  ageDays,
  binLine,
  binMarkers,
  binnedMarkers,
  byDate,
  dropBinned,
  freshValidity,
  MARKER_CAP,
  markerBytes,
  markerFile,
  oldestMarkerLine,
  overCap,
  purgeDue,
  republishDue,
  sequencesLine,
} from './markers';
import { SoakFailure } from './reasons';
import { namePrefix, OBSERVER_DIR_ENV, observerModule, recordUrl } from './recordReader';

const NAME = 'k51qzi5uqu5dlvj2baxnqndepeb86cbk3ng7n3i46uzyxzyqj2xjonzllnv0v8';
const DAY_MS = 86_400_000;

function marker(date: string, sequence = 1): Marker {
  return { date, ipnsName: NAME, sequence };
}

/** `count` consecutive days from 2026-01-01. */
function days(count: number): string[] {
  return Array.from({ length: count }, (_, i) =>
    new Date(Date.UTC(2026, 0, 1) + i * DAY_MS).toISOString().slice(0, 10)
  );
}

describe('a marker', () => {
  it('is named and filled by its day alone', () => {
    expect(markerFile('2026-09-30')).toBe('marker-2026-09-30.txt');
    expect(new TextDecoder().decode(markerBytes('2026-09-30'))).toBe(
      'cipherbox soak marker 2026-09-30\n'
    );
    expect(markerBytes('2026-09-30')).not.toEqual(markerBytes('2026-10-01'));
  });

  it('ages in whole UTC days, across a month and a leap day', () => {
    expect(ageDays('2026-09-30', '2026-09-30')).toBe(0);
    expect(ageDays('2026-09-28', '2026-10-01')).toBe(3);
    expect(ageDays('2028-02-28', '2028-03-01')).toBe(2);
  });

  it('falls due for the republish check past 60 days only', () => {
    expect(republishDue(marker('2026-01-01'), '2026-03-02')).toBe(false);
    expect(ageDays('2026-01-01', '2026-03-03')).toBe(61);
    expect(republishDue(marker('2026-01-01'), '2026-03-03')).toBe(true);
  });

  it('reads a validity as fresh only past the renewal threshold', () => {
    const now = Date.UTC(2026, 8, 30);
    expect(freshValidity(null, now)).toBe(false);
    expect(freshValidity(BigInt(now + 30 * DAY_MS), now)).toBe(false);
    expect(freshValidity(BigInt(now + 30 * DAY_MS + 1), now)).toBe(true);
    expect(freshValidity(BigInt(now + 90 * DAY_MS), now)).toBe(true);
  });
});

describe('the marker cap', () => {
  it(`keeps the newest ${MARKER_CAP} and bins the rest, oldest first`, () => {
    const all = days(MARKER_CAP + 2).map((day) => marker(day));
    expect(overCap(all.slice(0, MARKER_CAP))).toEqual([]);
    expect(overCap([...all].reverse()).map((m) => m.date)).toEqual(['2026-01-01', '2026-01-02']);
  });

  it('orders markers by day whatever the ledger order', () => {
    expect(byDate([marker('2026-02-01'), marker('2026-01-01')]).map((m) => m.date)).toEqual([
      '2026-01-01',
      '2026-02-01',
    ]);
  });
});

describe('the binned lines', () => {
  const ledger = [marker('2026-01-01', 3), marker('2026-01-02', 4)].reduce(
    appendMarker,
    emptyLedger()
  );

  it('swap a marker line for a binned line that reads back', () => {
    const binned = parseLedger(formatLedger(binMarkers(ledger, ['2026-01-01'], '2026-04-01')));
    expect(markers(binned)).toEqual([marker('2026-01-02', 4)]);
    expect(binnedMarkers(binned)).toEqual([{ date: '2026-01-01', binnedOn: '2026-04-01' }]);
  });

  it('leave the ledger once the purge is proven', () => {
    const binned = binMarkers(ledger, ['2026-01-01', '2026-01-02'], '2026-04-01');
    const left = dropBinned(binned, ['2026-01-01']);
    expect(binnedMarkers(left)).toEqual([{ date: '2026-01-02', binnedOn: '2026-04-01' }]);
    expect(markers(left)).toEqual([]);
  });

  it('keep a line of another shape', () => {
    const kept = parseLedger(
      `${formatLedger(emptyLedger())}shared-link https://app.example.test/s/abc\n`
    );
    expect(binnedMarkers(kept)).toEqual([]);
    expect(dropBinned(kept, ['2026-01-01'])).toEqual(kept);
  });

  it.each(['binned 2026-01-01', 'binned 2026-02-30 2026-04-01', 'binned x 2026-04-01'])(
    'refuse %j as ledger-unparsable',
    (text) => {
      const bad = { lines: [{ kind: 'other' as const, text }] };
      expect(() => binnedMarkers(bad)).toThrow(SoakFailure);
      expect(() => binnedMarkers(bad)).toThrow('[ledger-unparsable]');
    }
  );
});

describe('the purge due date', () => {
  const entry = { date: '2026-01-01', binnedOn: '2026-04-01' };

  it('falls on the first day after the retention ends', () => {
    expect(purgeDue(entry, 30, '2026-05-01')).toBe(false);
    expect(purgeDue(entry, 30, '2026-05-02')).toBe(true);
    expect(purgeDue(entry, 30, '2026-06-01')).toBe(true);
  });

  it('follows the saved retention', () => {
    expect(purgeDue(entry, 7, '2026-04-09')).toBe(true);
    expect(purgeDue(entry, 60, '2026-05-02')).toBe(false);
  });
});

describe('the summary lines', () => {
  it('name the oldest marker and its age', () => {
    expect(oldestMarkerLine(undefined, '2026-09-30')).toBe('no marker yet');
    expect(oldestMarkerLine(marker('2026-09-27'), '2026-09-30')).toBe(
      '2026-09-27, 3 days old, opened from a cold client'
    );
  });

  it('count the names a renewal advanced and name the newest', () => {
    expect(sequencesLine([])).toBe('no marker yet');
    expect(
      sequencesLine([
        { date: '2026-09-29', ledger: 1, resolved: 1n },
        { date: '2026-07-01', ledger: 1, resolved: 2n },
      ])
    ).toBe(
      '2 names at or above the ledger, 1 advanced by a renewal; newest 2026-09-29 at 1 (ledger 1)'
    );
  });

  it('count the purged and the waiting markers', () => {
    expect(binLine(3, 1, 30)).toBe('1 purged when due, 2 waiting; retention 30 days');
  });
});

describe('the public routing read', () => {
  it('asks delegated-ipfs.dev for the record of a name', () => {
    expect(recordUrl(NAME)).toBe(`https://delegated-ipfs.dev/routing/v1/ipns/${NAME}`);
  });

  it('names a record in an error by a short prefix only', () => {
    expect(namePrefix(NAME)).toBe('k51qzi5uqu5d...');
    expect(namePrefix(NAME)).not.toContain(NAME.slice(12));
  });

  it('loads the observer module from the configured folder', () => {
    expect(observerModule({ [OBSERVER_DIR_ENV]: '/opt/observer' })).toEqual({
      glue: join('/opt/observer', 'cipherbox_wasm.js'),
      wasm: join('/opt/observer', 'cipherbox_wasm_bg.wasm'),
    });
    expect(observerModule({}).glue).toMatch(/packages[/\\]client[/\\]test[/\\]browser[/\\]pkg/);
  });
});
