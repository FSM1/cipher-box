import { describe, expect, it } from 'vitest';
import { breachesOf, parseLoadReport, renderTable, type LoadReport } from './report';

const REPORT = {
  scenario: 'mixed',
  target: 'local',
  clients: 5,
  opsPerClient: 20,
  blockBytes: 65536,
  wallMs: 2712.4,
  thresholds: { p95Ms: 2000, maxErrorRate: 0.01 },
  breaches: [],
  operations: [
    {
      op: 'content-upload',
      count: 100,
      ok: 100,
      throttled: 0,
      failed: 0,
      p50Ms: 36.7,
      p95Ms: 86.3,
      p99Ms: 127.8,
      maxMs: 131,
      opsPerSec: 37.03,
      bytes: 6553600,
      bytesPerSec: 2428148,
      firstFailure: null,
    },
  ],
};

function reportJson(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({ ...REPORT, ...overrides });
}

describe('parseLoadReport', () => {
  it('reads the fields a baseline row is built from', () => {
    const report = parseLoadReport(reportJson());
    expect(report.scenario).toBe('mixed');
    expect(report.operations[0].p95Ms).toBe(86.3);
    expect(report.operations[0].opsPerSec).toBe(37.03);
  });

  it('refuses a report whose operation lost a percentile', () => {
    const operations = [{ ...REPORT.operations[0], p95Ms: null }];
    expect(() => parseLoadReport(reportJson({ operations }))).toThrow(/p95Ms is not a finite/);
  });

  it('refuses a percentile that is not a number', () => {
    const operations = [{ ...REPORT.operations[0], p50Ms: 'fast' }];
    expect(() => parseLoadReport(reportJson({ operations }))).toThrow(/p50Ms is not a finite/);
  });

  it('refuses a report with no operations array', () => {
    expect(() => parseLoadReport(reportJson({ operations: undefined }))).toThrow(
      /operations is not an array/
    );
  });
});

describe('renderTable', () => {
  it('writes one row per operation, with the scenario that measured it', () => {
    const table = renderTable([parseLoadReport(reportJson())]);
    const rows = table.split('\n');
    expect(rows).toHaveLength(3);
    expect(rows[2]).toBe(
      '| `mixed` | `content-upload` | 100 | 0 | 0 | 36.7 | 86.3 | 127.8 | 37.0 |'
    );
  });

  it('holds the rows of every scenario it is given', () => {
    const one = parseLoadReport(reportJson());
    const two = parseLoadReport(reportJson({ scenario: 'name-wave' }));
    expect(renderTable([one, two]).split('\n')).toHaveLength(4);
  });
});

describe('breachesOf', () => {
  it('names the scenario each breach came from', () => {
    const reports: LoadReport[] = [
      parseLoadReport(reportJson({ breaches: ['error rate 74.07% exceeds the 1.00% band'] })),
    ];
    expect(breachesOf(reports)).toEqual(['mixed: error rate 74.07% exceeds the 1.00% band']);
  });
});
