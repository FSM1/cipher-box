/**
 * @cipherbox/sdk - Event system
 *
 * Typed event definitions and a simple emitter for SDK state changes.
 * Consumers subscribe to events to sync external state (e.g., Zustand stores)
 * with SDK-internal state changes.
 *
 * Design: No external dependencies. The emitter is synchronous and
 * subscriber errors are caught to prevent cascading failures.
 */

import type { BinEntry } from '@cipherbox/core';
import type { ResolvedChild } from './folder-listing';

/**
 * Union of all events emitted by the SDK.
 *
 * Events follow the pattern `domain:action` for easy filtering
 * by consumers who only care about specific domains.
 */
export type SdkEvent =
  | {
      type: 'folder:loaded';
      folderId: string;
      ipnsName: string;
      children: ResolvedChild[];
      sequenceNumber: bigint;
    }
  | {
      type: 'folder:updated';
      folderId: string;
      ipnsName: string;
      children: ResolvedChild[];
      sequenceNumber: bigint;
    }
  | { type: 'folder:deleted'; folderId: string }
  | {
      type: 'sharedFolder:updated';
      shareId: string;
      ipnsName: string;
      children: ResolvedChild[];
      sequenceNumber: bigint;
    }
  | { type: 'file:uploaded'; folderId: string; fileName: string; cid: string }
  | {
      type: 'files:batchUploaded';
      folderId: string;
      successes: Array<{ fileName: string; cid: string }>;
      failures: Array<{ fileName: string; error: string }>;
    }
  | { type: 'file:downloaded'; cid: string }
  | { type: 'bin:updated'; entries: BinEntry[] }
  | { type: 'share:reWrapFailed'; folderIpnsName: string; failedRecipients: string[] }
  | { type: 'pin:secondaryFailed'; cid: string; providerName: string; error: string }
  | { type: 'ipns:batchPublishFailed'; ipnsNames: string[]; error: Error }
  | { type: 'operation:start'; operation: string }
  | { type: 'operation:end'; operation: string; durationMs: number }
  | { type: 'error'; operation: string; error: Error };

/**
 * Handler function for SDK events.
 * Consumers implement this to react to state changes.
 */
export type SdkEventHandler = (event: SdkEvent) => void;

/**
 * Simple typed event emitter. No external dependencies.
 *
 * Consumers subscribe with on() and unsubscribe with off() or the
 * returned unsubscribe function. Handler errors are caught silently
 * to prevent one subscriber from crashing the SDK or other subscribers.
 */
export class SdkEventEmitter {
  private handlers: SdkEventHandler[] = [];

  /**
   * Subscribe to all SDK events.
   * @returns An unsubscribe function for convenience
   */
  on(handler: SdkEventHandler): () => void {
    this.handlers.push(handler);
    return () => this.off(handler);
  }

  /**
   * Unsubscribe a previously registered handler.
   */
  off(handler: SdkEventHandler): void {
    this.handlers = this.handlers.filter((h) => h !== handler);
  }

  /**
   * Emit an event to all subscribers.
   * Handler errors are caught and swallowed -- subscriber bugs
   * must not crash the SDK.
   */
  emit(event: SdkEvent): void {
    for (const handler of this.handlers) {
      try {
        handler(event);
      } catch {
        /* subscriber errors don't crash SDK */
      }
    }
  }

  /**
   * Remove all handlers. Called during client destroy().
   */
  removeAll(): void {
    this.handlers = [];
  }
}
