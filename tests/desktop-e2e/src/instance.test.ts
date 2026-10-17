import { describe, expect, it } from 'vitest';
import { announcedDataDir, childrenOf } from './instance';

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

describe('the children of a shell', () => {
  const ps = [
    '    1     0 Ss   /sbin/launchd',
    '  412   400 S    /usr/local/bin/go-nfsv4',
    '  413   400 Z    <defunct>',
    '  414   401 S    /usr/local/bin/go-nfsv4',
    '',
  ].join('\n');

  it('lists only the processes the shell started', () => {
    expect(childrenOf(ps, 400)).toEqual([
      { pid: 412, zombie: false, command: '/usr/local/bin/go-nfsv4' },
      { pid: 413, zombie: true, command: '<defunct>' },
    ]);
  });

  it('is empty for a shell that started nothing', () => {
    expect(childrenOf(ps, 999)).toEqual([]);
  });
});
