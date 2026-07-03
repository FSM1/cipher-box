/**
 * Kind cache — file-vs-folder discrimination (D-02).
 *
 * `SealedChildRef` (frozen, NODE-03) carries no `kind` field — kind lives on
 * the child's own `PublishedNode` envelope (plaintext, top-level, no
 * unsealing required). This module resolves each child's kind once at
 * folder-load and memoizes it by `ipnsName` so `isFileRef` (fileTypes.ts)
 * can read it back synchronously — no async ripple through the component
 * tree (design decision D-02, resolved in 68.1-04-PLAN.md).
 *
 * Resolution is web-native (not sdk-core): `resolveIpnsRecord` (ipns.service)
 * applies the ROT-07 anti-rollback gate using the child's own
 * `SealedChildRef.generation`/`versionFloor` mirror, matching the
 * generation-source rule used everywhere else in the read-chain
 * (navigateReadChain, client.ts dfsFindFolder). `fetchFromIpfs` (lib/api/ipfs)
 * is the web's ctx-free IPFS relay client.
 *
 * Best-effort: a resolve failure for one ref leaves it uncached — callers
 * fall back to the folder-safe `false` default in `isFileRef`.
 * `resolveKinds(children)` is wired into the folder-load / navigation render
 * paths (68.1-14) and the sync/resync inserters (68.1-33).
 */
import type { SealedChildRef, PublishedNode } from '@cipherbox/core';
import { resolveIpnsRecord } from '../services/ipns.service';
import { fetchFromIpfs } from './api/ipfs';

export type Kind = 'file' | 'folder';

/** Module-level memoization: ipnsName -> resolved kind. */
const kindCache = new Map<string, Kind>();

/** Number of concurrent in-flight resolves when populating the cache in bulk. */
const RESOLVE_CONCURRENCY = 6;

/** Read a previously resolved kind, or `undefined` if not yet cached. */
export function getKind(ipnsName: string): Kind | undefined {
  return kindCache.get(ipnsName);
}

/**
 * Resolve and memoize the kind of every ref not already cached, with bounded
 * concurrency. Best-effort — a failed resolve for one ref is swallowed and
 * simply leaves that ref uncached (folder-safe miss default applies at read
 * time in `isFileRef`); it never fails the whole batch.
 */
export async function resolveKinds(refs: SealedChildRef[]): Promise<void> {
  const pending = refs.filter((ref) => !kindCache.has(ref.ipnsName));
  if (pending.length === 0) return;

  let cursor = 0;
  async function worker(): Promise<void> {
    while (cursor < pending.length) {
      const ref = pending[cursor++];
      try {
        const resolved = await resolveIpnsRecord(ref.ipnsName, {
          generation: ref.generation,
          versionFloor: Number(ref.versionFloor),
        });
        if (!resolved) continue;

        const raw = await fetchFromIpfs(resolved.cid);
        const envelope = JSON.parse(new TextDecoder().decode(raw)) as Pick<PublishedNode, 'kind'>;
        if (envelope.kind === 'file' || envelope.kind === 'folder') {
          kindCache.set(ref.ipnsName, envelope.kind);
        }
        // 'root' (or any other unexpected value) is never a valid child kind —
        // left uncached, folder-safe default applies.
      } catch {
        // Best-effort — leave uncached; the caller's row renders folder-safe.
      }
    }
  }

  const workerCount = Math.min(RESOLVE_CONCURRENCY, pending.length);
  await Promise.all(Array.from({ length: workerCount }, worker));
}

/** Clear the cache (e.g. on logout — avoids stale kind data across sessions). */
export function clearKindCache(): void {
  kindCache.clear();
}
