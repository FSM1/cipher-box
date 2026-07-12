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
 * user-configured IPFS gateway at runtime — no public CDN, no CipherBox API,
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
// The spliced bundle is wrapped in these markers so the build stays re-runnable:
// the first run replaces the bare placeholder; every subsequent run replaces the
// content between the markers, keeping the shipped self-contained file in sync
// with edits to main.ts/walk.ts without needing to restore the source template.
const markerStart = '<!-- RECOVERY_BUNDLE:START -->';
const markerEnd = '<!-- RECOVERY_BUNDLE:END -->';
const markerRe = /<!-- RECOVERY_BUNDLE:START -->[\s\S]*?<!-- RECOVERY_BUNDLE:END -->/;

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

  // Fail closed on any public-CDN runtime dependency slipping into the bundle
  // (Pitfall 1 / D-01). The needle is assembled at runtime so this guard source
  // itself carries zero literal CDN-host substring (keeps recovery-src CDN-free).
  const cdnNeedle = ['cdn', 'jsdelivr', 'net'].join('.');
  if (bundleCode.includes(cdnNeedle)) {
    throw new Error(
      `[recovery:build] bundle references ${cdnNeedle} — the tool must be fully self-contained (D-01).`
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

  const markedBlock = `${markerStart}\n<script type="module">\n${bundleCode}\n</script>\n${markerEnd}`;

  let splicedHtml: string;
  if (markerRe.test(html)) {
    // Re-splice: replace the previously-inlined bundle block in place.
    splicedHtml = html.replace(markerRe, markedBlock);
  } else if (html.includes(placeholder)) {
    // First splice: replace the bare placeholder with the marked bundle block.
    splicedHtml = html.replace(placeholder, markedBlock);
  } else {
    console.log(
      `[recovery:build] neither placeholder "${placeholder}" nor bundle markers present in recovery.html — skipping html-splice.`
    );
    return;
  }

  await writeFile(htmlPath, splicedHtml, 'utf8');
  console.log('[recovery:build] spliced bundle into recovery.html.');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
