import { describe, expect, it } from 'vitest';
import { archiveName, bootstrapRequested, planRun, soakFolderListed } from './bootstrap';

describe('the bootstrap decision', () => {
  it('reads SOAK_BOOTSTRAP as the workflow boolean, unset as false', () => {
    expect(bootstrapRequested({})).toBe(false);
    expect(bootstrapRequested({ SOAK_BOOTSTRAP: '' })).toBe(false);
    expect(bootstrapRequested({ SOAK_BOOTSTRAP: 'false' })).toBe(false);
    expect(bootstrapRequested({ SOAK_BOOTSTRAP: 'true' })).toBe(true);
  });

  it.each(['1', 'yes', 'TRUE', ' true'])('refuses SOAK_BOOTSTRAP=%j', (value) => {
    expect(() => bootstrapRequested({ SOAK_BOOTSTRAP: value })).toThrow(/SOAK_BOOTSTRAP/);
  });

  it('refuses a run with no ledger and no bootstrap, whatever else the vault holds', () => {
    const refuse = { kind: 'refuse', reason: 'unbootstrapped-or-wiped' };
    expect(planRun(false, { soakFolder: false, ledger: false })).toEqual(refuse);
    expect(planRun(false, { soakFolder: true, ledger: false })).toEqual(refuse);
  });

  it('resumes a run that finds the ledger', () => {
    expect(planRun(false, { soakFolder: true, ledger: true })).toEqual({ kind: 'resume' });
  });

  it('archives an existing soak folder on a bootstrap, and only then', () => {
    expect(planRun(true, { soakFolder: true, ledger: true })).toEqual({
      kind: 'bootstrap',
      archive: true,
    });
    expect(planRun(true, { soakFolder: true, ledger: false })).toEqual({
      kind: 'bootstrap',
      archive: true,
    });
    expect(planRun(true, { soakFolder: false, ledger: false })).toEqual({
      kind: 'bootstrap',
      archive: false,
    });
  });

  it('names the archive by day, and counts past a name an earlier bootstrap took', () => {
    expect(archiveName('2026-09-29', new Set(['soak']))).toBe('soak-archived-2026-09-29');
    expect(
      archiveName(
        '2026-09-29',
        new Set(['soak', 'soak-archived-2026-09-29', 'soak-archived-2026-09-29-2'])
      )
    ).toBe('soak-archived-2026-09-29-3');
  });

  it('trusts the row wait unless the settled listing contradicts it', () => {
    expect(soakFolderListed(true, new Set(['soak']))).toBe(true);
    expect(soakFolderListed(false, new Set(['soak-archived-2026-09-29']))).toBe(false);
    expect(() => soakFolderListed(false, new Set(['soak']))).toThrow('[listing-unsettled]');
  });
});
