/**
 * Browsing for a destination folder: one lazy `setFocus` + `snapshot` per
 * candidate parent, so the walk sees each folder as the engine has it and no
 * client-side tree is ever built (blueprint/web-client.md "UI state law").
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { SnapshotDescriptor } from '@cipherbox/client';
import { errorMessage } from '../lib/errorMessage';
import { sameNode } from '../lib/nodeId';
import { useEngine } from '../providers/EngineProvider';
import { listingRows, type ListingRow } from '../vault/listing';

export interface FolderPicker {
  /** True while the picker still sits on the folder it opened from. */
  atHome: boolean;
  folders: ListingRow[];
  /** The folder a command would target, or `null` until the listing lands. */
  destination: Uint8Array | null;
  /** Name of that folder, or `null` until the listing lands. */
  destinationName: string | null;
  isLoading: boolean;
  error: string | null;
  isRoot: boolean;
  enter(node: Uint8Array): void;
  leave(): void;
}

/**
 * @param openOn the folder to start on and to hand the focus window back to,
 * captured on mount
 * @param excludedKey a subtree the picker must not offer, by hex node id —
 * hiding the node hides everything under it, since the walk only descends
 * through what it lists
 */
export function useFolderPicker(openOn: Uint8Array | null, excludedKey: string): FolderPicker {
  const client = useEngine();
  const home = useRef(openOn).current;
  const [cursor, setCursor] = useState<Uint8Array | null>(home);
  const [listing, setListing] = useState<SnapshotDescriptor | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (client === null) return;
    let live = true;
    setListing(null);
    setError(null);
    client.facade
      .setFocus(cursor)
      .then(() => client.facade.snapshot(cursor))
      .then(
        (view) => {
          if (live) setListing(view);
        },
        (failure: unknown) => {
          if (live) setError(errorMessage(failure));
        }
      );
    return () => {
      live = false;
    };
  }, [client, cursor]);

  useEffect(() => () => void client?.facade.setFocus(home), [client, home]);

  const folders = useMemo(
    () =>
      listingRows(listing?.children ?? []).filter(
        (row) => row.kind === 'folder' && row.key !== excludedKey
      ),
    [listing, excludedKey]
  );

  return {
    atHome: sameNode(cursor, home),
    folders,
    destination: listing?.folder ?? null,
    destinationName: listing?.folderName ?? null,
    isLoading: listing === null && error === null,
    error,
    isRoot: listing !== null && sameNode(listing.folder, listing.root),
    enter: useCallback((node: Uint8Array) => setCursor(node), []),
    leave: useCallback(() => setCursor(listing?.ancestors[0]?.id ?? null), [listing]),
  };
}
