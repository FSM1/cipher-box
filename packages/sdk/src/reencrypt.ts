/**
 * @cipherbox/sdk - FileMetadata re-encryption on folder change
 *
 * A file's per-file `FileMetadata` IPNS record is AES-256-GCM sealed with its
 * PARENT folder's `folderKey`; the decrypt path uses the key of whichever folder
 * lists the pointer. Whenever a file changes parent folder — a cross-folder
 * `moveItem`, or a `restoreFromBin` to a folder other than the original parent —
 * the record must be re-sealed under the destination `folderKey`, or every later
 * decrypt under that folder fails with `CryptoError: Decryption failed`.
 *
 * Shared by `CipherBoxClient.moveItem` and `restoreFromBin` so both paths get the
 * same idempotent retry semantics.
 */

import * as sdkCore from '@cipherbox/sdk-core';
import type { SdkContext } from '@cipherbox/sdk-core';
import type { FileMetadata } from '@cipherbox/core';

/**
 * True for the AES-GCM wrong-key decrypt failure (`CryptoError` with code
 * `'DECRYPTION_FAILED'`, from `@cipherbox/crypto`).
 *
 * Matches the `.code`, not the message: the message is intentionally generic to
 * avoid a padding oracle, so it is not a reliable discriminator. Duck-typed on
 * `.code` rather than `instanceof CryptoError` so the check can never throw under
 * a partial test mock of `@cipherbox/crypto`, and so a missing-record error
 * (a plain `Error` with no `.code`) correctly does NOT match.
 */
function isDecryptionFailure(err: unknown): boolean {
  return err instanceof Error && (err as { code?: unknown }).code === 'DECRYPTION_FAILED';
}

/**
 * Re-seal a file's `FileMetadata` IPNS record from `sourceFolderKey` to
 * `destFolderKey` (no version bump — re-keying is not a content change).
 *
 * Idempotent. If the record no longer decrypts under the source key, a prior
 * partial attempt may have already re-keyed it to the destination: this confirms
 * the record decrypts under the destination key and, if so, treats the
 * re-encryption as already complete (so a retry after a partial failure finishes
 * the move cleanly instead of throwing). A genuinely unreadable record — missing,
 * or undecryptable under BOTH keys — propagates the original error.
 *
 * Does NOT own `fileIpnsPrivateKey`: the caller unwraps it and clears it in a
 * `finally`. `updateFileMetadata` zeroes it on the re-key path; on the
 * already-re-keyed path it is never consumed, so the caller's `finally` is the
 * only thing that clears it.
 */
export async function reencryptFileMetadataForFolderChange(params: {
  fileMetaIpnsName: string;
  fileIpnsPrivateKey: Uint8Array;
  sourceFolderKey: Uint8Array;
  destFolderKey: Uint8Array;
  ctx: SdkContext;
}): Promise<void> {
  let currentMetadata: FileMetadata;
  try {
    ({ metadata: currentMetadata } = await sdkCore.resolveFileMetadata(
      params.fileMetaIpnsName,
      params.sourceFolderKey,
      params.ctx
    ));
  } catch (err) {
    if (!isDecryptionFailure(err)) throw err;
    // Source-key decrypt failed. A prior partial attempt may have already
    // re-keyed the record to the destination — confirm by resolving under the
    // destination key. Success ⇒ re-encryption already done (idempotent retry);
    // failure ⇒ the record is genuinely unreadable and the original error stands.
    try {
      await sdkCore.resolveFileMetadata(params.fileMetaIpnsName, params.destFolderKey, params.ctx);
    } catch {
      throw err;
    }
    return;
  }

  await sdkCore.updateFileMetadata({
    fileIpnsPrivateKey: params.fileIpnsPrivateKey,
    fileMetaIpnsName: params.fileMetaIpnsName,
    folderKey: params.destFolderKey,
    currentMetadata,
    updates: {},
    createVersion: false,
    ctx: params.ctx,
  });
}
