/**
 * @cipherbox/core - Child Write-Key Seal Round-Trip and Role-0x04 KAT
 *
 * TDD suite (RED phase): tests for WRITE-01.
 * This file imports sealChildWriteKey / unsealChildWriteKey which do NOT exist yet;
 * the suite is expected to fail (RED) until Task 2 provides those functions.
 *
 * Requirements coverage:
 *   WRITE-01: sealChildWriteKey / unsealChildWriteKey with role byte 0x04
 *
 * Security invariants tested:
 *   T-65-01: Write link sealed under parentWriteKey; cross-role rejection proves isolation
 *   T-65-02: Role 0x04 frozen — role-0x02 blob fails role-0x04 unseal
 *   T-65-03: AAD binds childId / childKind / childGeneration — mismatch throws
 *   T-65-04: D-09 terminal-owner — input buffers not zeroed after call
 */

import { describe, it, expect } from 'vitest';
import {
  sealChildWriteKey,
  unsealChildWriteKey,
  sealChildReadKey,
  unsealChildReadKey,
} from '../node/seal';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** 32-byte childWriteKey filled with 0xAB (deterministic for tests). */
const CHILD_WRITE_KEY = new Uint8Array(32).fill(0xab);

/** 32-byte parentWriteKey filled with 0xCD (deterministic for tests). */
const PARENT_WRITE_KEY = new Uint8Array(32).fill(0xcd);

/** A different 32-byte parentWriteKey (wrong key for rejection tests). */
const WRONG_PARENT_WRITE_KEY = new Uint8Array(32).fill(0xef);

/** Fixed hyphenated UUID child ID. */
const CHILD_ID = '550e8400-e29b-41d4-a716-446655440000';

/** A different child ID for AAD-mismatch tests. */
const OTHER_CHILD_ID = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';

const CHILD_KIND = 'folder' as const;
const CHILD_GENERATION = 0;

// ---------------------------------------------------------------------------
// Round-trip: sealChildWriteKey → unsealChildWriteKey
// ---------------------------------------------------------------------------

describe('sealChildWriteKey / unsealChildWriteKey', () => {
  it('round-trips: seal then unseal returns the original 32-byte childWriteKey', async () => {
    const sealed = await sealChildWriteKey(
      CHILD_WRITE_KEY,
      PARENT_WRITE_KEY,
      CHILD_ID,
      CHILD_KIND,
      CHILD_GENERATION
    );
    expect(typeof sealed).toBe('string');

    const recovered = await unsealChildWriteKey(
      sealed,
      PARENT_WRITE_KEY,
      CHILD_ID,
      CHILD_KIND,
      CHILD_GENERATION
    );

    expect(recovered).toBeInstanceOf(Uint8Array);
    expect(recovered.length).toBe(32);
    expect(Array.from(recovered)).toEqual(Array.from(CHILD_WRITE_KEY));
  });

  // ---------------------------------------------------------------------------
  // Role isolation (T-65-01 / T-65-02)
  // ---------------------------------------------------------------------------

  it('role isolation: a blob from sealChildReadKey (role 0x02) fails unsealChildWriteKey (role 0x04)', async () => {
    // Seal using the READ-key primitive (role 0x02)
    const readKeyBlob = await sealChildReadKey(
      CHILD_WRITE_KEY,
      PARENT_WRITE_KEY,
      CHILD_ID,
      CHILD_KIND,
      CHILD_GENERATION
    );

    // Attempt to unseal with WRITE-key primitive (role 0x04) — must throw
    await expect(
      unsealChildWriteKey(readKeyBlob, PARENT_WRITE_KEY, CHILD_ID, CHILD_KIND, CHILD_GENERATION)
    ).rejects.toThrow();
  });

  it('role isolation: a blob from sealChildWriteKey (role 0x04) fails unsealChildReadKey (role 0x02)', async () => {
    const writeKeyBlob = await sealChildWriteKey(
      CHILD_WRITE_KEY,
      PARENT_WRITE_KEY,
      CHILD_ID,
      CHILD_KIND,
      CHILD_GENERATION
    );

    // Attempt to unseal with READ-key primitive (role 0x02) — must throw
    await expect(
      unsealChildReadKey(writeKeyBlob, PARENT_WRITE_KEY, CHILD_ID, CHILD_KIND, CHILD_GENERATION)
    ).rejects.toThrow();
  });

  // ---------------------------------------------------------------------------
  // AAD binding (T-65-03)
  // ---------------------------------------------------------------------------

  it('AAD binding: throws when childId does not match sealing metadata', async () => {
    const sealed = await sealChildWriteKey(
      CHILD_WRITE_KEY,
      PARENT_WRITE_KEY,
      CHILD_ID,
      CHILD_KIND,
      CHILD_GENERATION
    );

    await expect(
      unsealChildWriteKey(sealed, PARENT_WRITE_KEY, OTHER_CHILD_ID, CHILD_KIND, CHILD_GENERATION)
    ).rejects.toThrow();
  });

  it('AAD binding: throws when childKind does not match sealing metadata', async () => {
    const sealed = await sealChildWriteKey(
      CHILD_WRITE_KEY,
      PARENT_WRITE_KEY,
      CHILD_ID,
      CHILD_KIND,
      CHILD_GENERATION
    );

    await expect(
      unsealChildWriteKey(sealed, PARENT_WRITE_KEY, CHILD_ID, 'file', CHILD_GENERATION)
    ).rejects.toThrow();
  });

  it('AAD binding: throws when childGeneration does not match sealing metadata', async () => {
    const sealed = await sealChildWriteKey(
      CHILD_WRITE_KEY,
      PARENT_WRITE_KEY,
      CHILD_ID,
      CHILD_KIND,
      CHILD_GENERATION
    );

    await expect(
      unsealChildWriteKey(sealed, PARENT_WRITE_KEY, CHILD_ID, CHILD_KIND, 99)
    ).rejects.toThrow();
  });

  it('AAD binding: throws when wrong parentWriteKey is supplied', async () => {
    const sealed = await sealChildWriteKey(
      CHILD_WRITE_KEY,
      PARENT_WRITE_KEY,
      CHILD_ID,
      CHILD_KIND,
      CHILD_GENERATION
    );

    await expect(
      unsealChildWriteKey(sealed, WRONG_PARENT_WRITE_KEY, CHILD_ID, CHILD_KIND, CHILD_GENERATION)
    ).rejects.toThrow();
  });

  // ---------------------------------------------------------------------------
  // Terminal-owner: input buffers not zeroed after call (T-65-04 / D-09)
  // ---------------------------------------------------------------------------

  it('terminal-owner: childWriteKey and parentWriteKey buffers are unchanged after sealChildWriteKey', async () => {
    const childKeyCopy = CHILD_WRITE_KEY.slice();
    const parentKeyCopy = PARENT_WRITE_KEY.slice();

    await sealChildWriteKey(
      CHILD_WRITE_KEY,
      PARENT_WRITE_KEY,
      CHILD_ID,
      CHILD_KIND,
      CHILD_GENERATION
    );

    expect(Array.from(CHILD_WRITE_KEY)).toEqual(Array.from(childKeyCopy));
    expect(Array.from(PARENT_WRITE_KEY)).toEqual(Array.from(parentKeyCopy));
  });

  it('terminal-owner: parentWriteKey buffer is unchanged after unsealChildWriteKey', async () => {
    const sealed = await sealChildWriteKey(
      CHILD_WRITE_KEY,
      PARENT_WRITE_KEY,
      CHILD_ID,
      CHILD_KIND,
      CHILD_GENERATION
    );

    const parentKeyCopy = PARENT_WRITE_KEY.slice();

    await unsealChildWriteKey(sealed, PARENT_WRITE_KEY, CHILD_ID, CHILD_KIND, CHILD_GENERATION);

    expect(Array.from(PARENT_WRITE_KEY)).toEqual(Array.from(parentKeyCopy));
  });
});
