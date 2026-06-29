/**
 * TDD tests for moveItem destination-parent re-seal of a moved child readKey (FLAG-63-U2).
 *
 * Phase 64 Plan 01 Task 3.
 *
 * Background: when a child node is moved between two folders, the child's
 * `SealedChildRef.readKeySealed` blob is sealed under the SOURCE parent's readKey.
 * After the move, any reader navigating via the DESTINATION parent's readKey
 * fails AEAD verification because the AAD includes the parent-role binding.
 * Fix: unseal under source key → re-seal under dest key; keep child id/kind/generation
 * unchanged (no content re-encryption, no generation bump).
 *
 * These tests verify the re-seal crypto contract using the REAL
 * `sealChildReadKey`/`unsealChildReadKey` primitives from @cipherbox/core.
 * They are a pure in-memory crypto round-trip (no network, no IPNS, no live stack).
 *
 * RED phase: written before client.ts moveItem calls the re-seal primitives.
 * The primitives themselves are already implemented, so these tests pass on first run —
 * they document the desired crypto contract that the client.ts implementation MUST satisfy.
 */

import { describe, it, expect } from 'vitest';
import { sealChildReadKey, unsealChildReadKey } from '@cipherbox/core';
import { CryptoError } from '@cipherbox/crypto';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** Stable UUID of the moved child node (normally read from the plaintext PublishedNode envelope). */
const CHILD_ID = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890';
const CHILD_KIND = 'folder' as const;
const CHILD_GENERATION = 3;

/** 32-byte readKey of the source parent folder. */
const SOURCE_PARENT_READ_KEY = new Uint8Array(32).fill(0x11);
/** 32-byte readKey of the destination parent folder. */
const DEST_PARENT_READ_KEY = new Uint8Array(32).fill(0x22);
/** 32-byte readKey of the moved child node (normally recovered from source parent). */
const CHILD_READ_KEY = new Uint8Array(32).fill(0x33);

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('moveItem destination-parent re-seal (FLAG-63-U2)', () => {
  /**
   * Test 1: Re-sealed blob unseals successfully under the DEST parent key.
   *
   * Simulates the full re-seal path:
   *   source-sealed  = sealChildReadKey(childReadKey, sourceKey, ...)
   *   childReadKey   = unsealChildReadKey(source-sealed, sourceKey, ...)  [recover]
   *   dest-sealed    = sealChildReadKey(childReadKey, destKey, ...)       [re-seal]
   *   recovered      = unsealChildReadKey(dest-sealed, destKey, ...)      [verify]
   *
   * Expected: `recovered` === `CHILD_READ_KEY`
   */
  it('re-sealed child readKey unseals under the DEST parent key', async () => {
    // Seal under source parent (as would happen when the child was originally added)
    const sourceSealed = await sealChildReadKey(
      CHILD_READ_KEY,
      SOURCE_PARENT_READ_KEY,
      CHILD_ID,
      CHILD_KIND,
      CHILD_GENERATION
    );

    // Recover the child readKey using source parent (as client.ts does on moveItem)
    const recoveredChildKey = await unsealChildReadKey(
      sourceSealed,
      SOURCE_PARENT_READ_KEY,
      CHILD_ID,
      CHILD_KIND,
      CHILD_GENERATION
    );

    // Re-seal under the destination parent
    const destSealed = await sealChildReadKey(
      recoveredChildKey,
      DEST_PARENT_READ_KEY,
      CHILD_ID,
      CHILD_KIND,
      CHILD_GENERATION
    );

    // Verify: dest-sealed MUST unseal under dest key and return the original bytes
    const finalKey = await unsealChildReadKey(
      destSealed,
      DEST_PARENT_READ_KEY,
      CHILD_ID,
      CHILD_KIND,
      CHILD_GENERATION
    );

    expect(finalKey).toEqual(CHILD_READ_KEY);
  });

  /**
   * Test 2: Re-sealed blob FAILS `unsealChildReadKey` under the SOURCE key.
   *
   * After re-sealing under dest, the source-key unseal must throw (AEAD tag mismatch).
   * This proves the key binding has MOVED — source-scope readers can no longer derive
   * the child's readKey from the dest-parent's SealedChildRef (FLAG-63-U2 fix).
   */
  it('re-sealed child readKey FAILS unseal under the SOURCE parent key (binding moved)', async () => {
    // Seal under source parent
    const sourceSealed = await sealChildReadKey(
      CHILD_READ_KEY,
      SOURCE_PARENT_READ_KEY,
      CHILD_ID,
      CHILD_KIND,
      CHILD_GENERATION
    );

    // Recover using source parent
    const recoveredChildKey = await unsealChildReadKey(
      sourceSealed,
      SOURCE_PARENT_READ_KEY,
      CHILD_ID,
      CHILD_KIND,
      CHILD_GENERATION
    );

    // Re-seal under dest parent
    const destSealed = await sealChildReadKey(
      recoveredChildKey,
      DEST_PARENT_READ_KEY,
      CHILD_ID,
      CHILD_KIND,
      CHILD_GENERATION
    );

    // Verify: trying to unseal dest-sealed blob with source key MUST throw
    await expect(
      unsealChildReadKey(destSealed, SOURCE_PARENT_READ_KEY, CHILD_ID, CHILD_KIND, CHILD_GENERATION)
    ).rejects.toThrow(CryptoError);
  });

  /**
   * Test 3: The re-seal preserves the child node's id, kind, and generation unchanged.
   *
   * The re-seal operation MUST NOT alter any identity metadata of the moved node.
   * Only `readKeySealed` changes (bound to dest parent); the node's own
   * id/kind/generation remain stable (no content re-encryption, no generation bump).
   */
  it('re-seal preserves child node id, kind, and generation (no content re-encryption)', async () => {
    // Original SealedChildRef fields (simplified — only the identity-relevant ones)
    const originalRef = {
      id: CHILD_ID,
      kind: CHILD_KIND,
      generation: CHILD_GENERATION,
    };

    // Simulate the re-seal: recover readKey from source, seal under dest
    const sourceSealed = await sealChildReadKey(
      CHILD_READ_KEY,
      SOURCE_PARENT_READ_KEY,
      originalRef.id,
      originalRef.kind,
      originalRef.generation
    );
    const recoveredKey = await unsealChildReadKey(
      sourceSealed,
      SOURCE_PARENT_READ_KEY,
      originalRef.id,
      originalRef.kind,
      originalRef.generation
    );
    // Re-seal using the SAME id/kind/generation — these must not change
    const destSealed = await sealChildReadKey(
      recoveredKey,
      DEST_PARENT_READ_KEY,
      originalRef.id,
      originalRef.kind,
      originalRef.generation
    );

    // Verify: blob was produced; identity unchanged (same inputs used for both seal calls)
    expect(typeof destSealed).toBe('string');
    expect(destSealed.length).toBeGreaterThan(0);

    // Re-seal does NOT bump generation — AAD still uses originalRef.generation
    // Prove this by confirming the dest-sealed blob unseals with the ORIGINAL generation
    const verified = await unsealChildReadKey(
      destSealed,
      DEST_PARENT_READ_KEY,
      originalRef.id,
      originalRef.kind,
      originalRef.generation // unchanged generation
    );
    expect(verified).toEqual(CHILD_READ_KEY);

    // Bumped generation would break the AAD and throw — confirm generation was NOT bumped
    await expect(
      unsealChildReadKey(
        destSealed,
        DEST_PARENT_READ_KEY,
        originalRef.id,
        originalRef.kind,
        originalRef.generation + 1 // wrong generation
      )
    ).rejects.toThrow(CryptoError);
  });
});
