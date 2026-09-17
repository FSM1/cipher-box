/**
 * How every e2e suite serves a built bundle: one argument vector.
 *
 * The web suite and the cross-client suite both serve `apps/web` out of a built
 * directory, and a flag one of them needs must reach the other, or the two
 * suites serve the same artifact differently.
 */

/** The argv that serves one built directory on one port. */
export function previewArguments(outDir: string, port: number): string[] {
  return [
    '--filter',
    '@cipherbox/web',
    'exec',
    'vite',
    'preview',
    '--outDir',
    outDir,
    '--port',
    String(port),
    '--strictPort',
  ];
}

/** The same vector as one shell command, which is what a web server takes. */
export function previewCommand(outDir: string, port: number): string {
  return `pnpm ${previewArguments(outDir, port).join(' ')}`;
}
