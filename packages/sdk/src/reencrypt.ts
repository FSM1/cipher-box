/**
 * @cipherbox/sdk - FileMetadata re-encryption on folder change
 *
 * PHASE 62 STUB: Content self-seal (phase 65) removes re-encrypt-on-move.
 * The file Node's readKey is sealed under the parent's readKey chain, so
 * moving a file across folders is a pure child-ref re-seal under the dest
 * parent's write-body — no separate per-IPNS re-encrypt step.
 *
 * TODO(phase 65): rewire moveItem and restoreFromBin to use the write-chain
 * child-ref re-seal instead.
 */

import type { SdkContext } from '@cipherbox/sdk-core';

/**
 * Re-seal a file's metadata record from sourceFolderKey to destFolderKey.
 *
 * @stub phase 65 (move re-encrypt; content self-seal removes re-encrypt-on-move)
 */
export async function reencryptFileMetadataForFolderChange(params: {
  fileMetaIpnsName: string;
  fileIpnsPrivateKey: Uint8Array;
  sourceFolderKey: Uint8Array;
  destFolderKey: Uint8Array;
  ctx: SdkContext;
}): Promise<void> {
  void params;
  throw new Error(
    'not implemented — phase 65 (move re-encrypt; content self-seal removes re-encrypt-on-move)'
  );
}
