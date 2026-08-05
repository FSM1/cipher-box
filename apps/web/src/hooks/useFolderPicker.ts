/**
 * Browsing for a destination folder: one lazy `setFocus` + `snapshot` per
 * candidate parent, so the walk sees each folder as the engine has it and no
 * client-side tree is ever built (blueprint/web-client.md "UI state law").
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { SnapshotDescriptor } from '@cipherbox/client';
import { errorMessage } from '../lib/errorMessage';
import { sameNode } from '../lib/nodeId';
import { useEngine, useSnapshotStore } from '../providers/EngineProvider';
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
  /** True only when the picker knows which folder `leave` would land on. */
  canLeave: boolean;
  enter(node: Uint8Array): void;
  leave(): void;
}

/**
 * @param openOn the folder to start the walk on, captured on mount
 * @param excludedKey a subtree the picker must not offer, by hex node id —
 * hiding the node hides everything under it, since the walk only descends
 * through what it lists
 */
export function useFolderPicker(openOn: Uint8Array | null, excludedKey: string): FolderPicker {
  const client = useEngine();
  const store = useSnapshotStore();
  const home = useRef(openOn).current;
  const [cursor, setCursor] = useState<Uint8Array | null>(home);
  const [listing, setListing] = useState<SnapshotDescriptor | null>(null);
  const [error, setError] = useState<string | null>(null);
  // Every cursor change drops the listing, so the ancestors it carries cannot
  // be what walks the picker back out of a folder it descended into.
  const [descended, setDescended] = useState<(Uint8Array | null)[]>([]);

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

  // The walk borrows the focus window; the store owns it and takes it back.
  useEffect(() => () => store.refocus(), [store]);

  // The read effect retires the listing a render later than the cursor moves,
  // and a listing outliving its cursor names the folder just left as the
  // destination — so moving the cursor retires it in the same update.
  const navigate = useCallback((target: Uint8Array | null) => {
    setListing(null);
    setCursor(target);
  }, []);

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
    canLeave: descended.length > 0 || (listing !== null && !sameNode(listing.folder, listing.root)),
    enter: useCallback(
      (node: Uint8Array) => {
        setDescended((trail) => [...trail, cursor]);
        navigate(node);
      },
      [cursor, navigate]
    ),
    leave: useCallback(() => {
      if (descended.length > 0) {
        navigate(descended[descended.length - 1]);
        setDescended((trail) => trail.slice(0, -1));
        return;
      }
      // Climbing above where the picker opened needs the listing's own
      // ancestry; without it there is no parent to name, so it stays put.
      if (listing !== null) navigate(listing.ancestors[0]?.id ?? null);
    }, [descended, listing, navigate]),
  };
}
