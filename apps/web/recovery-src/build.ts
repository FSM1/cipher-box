/**
 * Recovery-tool bundler (SC1).
 *
 * Bundles the standalone `recovery-src/main.ts` entry — which pulls in the
 * low-level `@cipherbox/crypto` + `@cipherbox/core` primitives plus `fflate`
 * (D-03) — into a single self-contained browser script via esbuild, then
 * splices it into `public/recovery.html`'s `<!-- RECOVERY_BUNDLE -->`
 * placeholder as an inline `<script type="module">`.
 *
 * Trust-nothing / infra-independent (D-01/D-04): the emitted bundle carries
 * every dependency inline so the shipped tool depends only on the
 * user-configured IPFS gateway at runtime — no cdn.jsdelivr, no CipherBox API,
 * no SDK facade. This script itself imports NO SDK / sdk-core runtime.
 *
 * Run via: `pnpm --filter @cipherbox/web recovery:build` (invoked with tsx).
 */

import { build } from 'esbuild';
import { readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const entryPoint = resolve(scriptDir, 'main.ts');
const htmlPath = resolve(scriptDir, '..', 'public', 'recovery.html');
const placeholder = '<!-- RECOVERY_BUNDLE -->';

/** ~2 MB minified is the discretionary soft ceiling (D-04); over it is a flag, not a failure. */
const SIZE_FLAG_BYTES = 2 * 1024 * 1024;

async function main(): Promise<void> {
  const result = await build({
    entryPoints: [entryPoint],
    bundle: true,
    format: 'esm',
    platform: 'browser',
    target: 'es2022',
    minify: true,
    write: false,
    legalComments: 'none',
  });

  const output = result.outputFiles[0];
  if (!output) {
    throw new Error('esbuild produced no output file');
  }

  const bundleCode = output.text;
  const bundleBytes = output.contents.byteLength;

  console.log(
    `[recovery:build] bundle size: ${bundleBytes} bytes (${(bundleBytes / 1024).toFixed(1)} KiB)`
  );
  if (bundleBytes > SIZE_FLAG_BYTES) {
    console.warn(
      `[recovery:build] WARNING: bundle exceeds ~${SIZE_FLAG_BYTES} bytes soft ceiling — flag for review (D-04).`
    );
  }

  // Fail closed on any CDN runtime dependency slipping into the bundle (Pitfall 1 / D-01).
  if (bundleCode.includes('cdn.jsdelivr')) {
    throw new Error(
      '[recovery:build] bundle references cdn.jsdelivr — the tool must be fully self-contained (D-01).'
    );
  }

  // HTML splice — guarded no-op until the placeholder lands in recovery.html (plan 78-02).
  let html: string | null = null;
  try {
    html = await readFile(htmlPath, 'utf8');
  } catch {
    html = null;
  }

  if (html === null) {
    console.log(
      `[recovery:build] ${htmlPath} not found — skipping html-splice (bundle-only spike).`
    );
    return;
  }

  if (!html.includes(placeholder)) {
    console.log(
      `[recovery:build] placeholder "${placeholder}" absent in recovery.html — skipping html-splice (lands in plan 78-02).`
    );
    return;
  }

  const scriptTag = `<script type="module">\n${bundleCode}\n</script>`;
  const splicedHtml = html.replace(placeholder, scriptTag);
  await writeFile(htmlPath, splicedHtml, 'utf8');
  console.log('[recovery:build] spliced bundle into recovery.html.');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
