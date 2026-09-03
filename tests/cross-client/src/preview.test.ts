import { describe, expect, it } from 'vitest';
import { packageManager, previewArguments } from './preview';

describe('packageManager', () => {
  it('names the Windows wrapper on Windows, which has no extensionless entry', () => {
    expect(packageManager('win32')).toBe('pnpm.cmd');
  });

  it('names the plain binary elsewhere', () => {
    expect(packageManager('darwin')).toBe('pnpm');
    expect(packageManager('linux')).toBe('pnpm');
  });
});

describe('previewArguments', () => {
  it('serves the named directory on the named port', () => {
    const argv = previewArguments('dist', 4175);
    expect(argv).toContain('dist');
    expect(argv).toContain('4175');
  });

  it('pins the port, so a taken one fails rather than moving the bundle', () => {
    expect(previewArguments('dist', 4175)).toContain('--strictPort');
  });

  it('runs the web package, not whichever package holds the cwd', () => {
    const argv = previewArguments('dist', 4175);
    expect(argv.slice(0, 2)).toEqual(['--filter', '@cipherbox/web']);
  });
});
