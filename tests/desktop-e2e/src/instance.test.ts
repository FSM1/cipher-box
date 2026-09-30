import { describe, expect, it } from 'vitest';
import { announcedDataDir } from './instance';

describe('the announced data directory', () => {
  it('reads the data directory from the line the shell writes', () => {
    const log = 'starting\ne2e: home=/runner/a data_local=/runner/a/data\nmounted\n';
    expect(announcedDataDir(log)).toBe('/runner/a/data');
  });

  it('reads a Windows line with its carriage return', () => {
    const log = 'e2e: home=C:\\runner\\a data_local=C:\\runner\\a\\data\r\n';
    expect(announcedDataDir(log)).toBe('C:\\runner\\a\\data');
  });

  it('is null before the shell writes the line', () => {
    expect(announcedDataDir('')).toBeNull();
    expect(announcedDataDir('e2e: home=/runner/a')).toBeNull();
  });
});
