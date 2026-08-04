import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

import { MEDIA_WINDOW_BYTES } from './protocol.js';

/**
 * The engine's committed KAT manifest, which `crates/engine/tests/kat_content.rs`
 * pins against `ContentProfile::PRODUCTION.chunk_size()`. Reading it here closes
 * the loop, so the TS window and the Rust chunk cannot drift apart in silence.
 */
const manifestPath = new URL('../../../../crates/engine/kat/manifest.json', import.meta.url);

function productionChunkSize(): number {
  const manifest: unknown = JSON.parse(readFileSync(manifestPath, 'utf8'));
  const size = (manifest as { content?: { productionChunkSize?: unknown } }).content
    ?.productionChunkSize;
  if (typeof size !== 'number') {
    throw new Error('the engine KAT manifest no longer carries content.productionChunkSize');
  }
  return size;
}

describe('MEDIA_WINDOW_BYTES', () => {
  it('is exactly one engine content chunk', () => {
    // A window wider or narrower than a chunk makes every chunk-aligned read
    // straddle two leaves — silent 2x fetch amplification, not a wrong answer.
    expect(MEDIA_WINDOW_BYTES).toBe(productionChunkSize());
  });

  it('is a whole positive count of bytes', () => {
    expect(Number.isSafeInteger(MEDIA_WINDOW_BYTES)).toBe(true);
    expect(MEDIA_WINDOW_BYTES).toBeGreaterThan(0);
  });
});
