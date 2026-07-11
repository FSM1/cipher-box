/**
 * @cipherbox/sdk - Shared write context builder
 *
 * Takes explicit params to construct a SharedWriteContext for write operations.
 */

import type { SealedChildRef, PublishedNode } from '@cipherbox/core';
import type { SdkContext } from '@cipherbox/sdk-core';
import type { SharedWriteContext, PublishNodeResult } from './shared-write';

/**
 * Parameters for building a SharedWriteContext.
 * All the state that was previously read from React hooks.
 */
export type SharedWriteContextParams = {
  ctx: SdkContext;
  /** 32-byte AES key for sealing/unsealing the node's read-body (maps from folderKey) */
  readKey: Uint8Array;
  /** 32-byte AES key for sealing/unsealing the node's write-body */
  writeKey: Uint8Array;
  /** Current on-wire published envelope */
  publishedNode: PublishedNode;
  ipnsName: string;
  sequenceNumber: bigint;
  children: SealedChildRef[];
  ownerPublicKey: Uint8Array;
  recipientPublicKey: Uint8Array;
  shareId: string;
  publishNodeFn: (params: {
    published: PublishedNode;
    ipnsName: string;
    ipnsPrivateKey: Uint8Array;
    sequenceNumber: bigint;
  }) => Promise<PublishNodeResult>;
  addToIpfsFn: (data: Uint8Array) => Promise<{ cid: string }>;
};

/**
 * Build a SharedWriteContext from explicit parameters.
 *
 * The web hook wrapper handles null-checking of each field before calling this.
 * This function assumes all required fields are present.
 *
 * @param params - All required state for shared write operations
 * @returns SharedWriteContext ready for SDK shared-write operations
 */
export function buildSharedWriteContext(params: SharedWriteContextParams): SharedWriteContext {
  return {
    ctx: params.ctx,
    readKey: params.readKey,
    writeKey: params.writeKey,
    publishedNode: params.publishedNode,
    ipnsName: params.ipnsName,
    sequenceNumber: params.sequenceNumber,
    children: params.children,
    ownerPublicKey: params.ownerPublicKey,
    recipientPublicKey: params.recipientPublicKey,
    shareId: params.shareId,
    publishNodeFn: params.publishNodeFn,
    addToIpfsFn: params.addToIpfsFn,
  };
}
