/**
 * The vault browser's read path: the routed folder, the snapshot the engine
 * reports for it, and the navigation that moves both. The engine's focus window
 * follows the route — there is no client-side tree to walk, only the direct
 * children and the ancestor trail the snapshot carries.
 */

import { useCallback, useEffect, useMemo } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import type { BreadcrumbDescriptor } from '@cipherbox/client';
import type { SnapshotError } from '../engine/snapshotStore';
import { useSnapshot } from '../engine/useSnapshot';
import { folderPath, folderRoute, sameNode } from '../lib/nodeId';
import { useSnapshotStore } from '../providers/EngineProvider';
import { listingRows, type ListingRow } from './listing';

const NOT_A_FOLDER: SnapshotError = { message: 'that is not a folder id' };

export interface FolderNavigation {
  /** Direct children of the routed folder, folders first. */
  rows: ListingRow[];
  /** The folder the snapshot listed, or `null` until one lands for this route. */
  folder: Uint8Array | null;
  /** Root-first trail, ending at the folder on screen. */
  breadcrumbs: BreadcrumbDescriptor[];
  /** True until the engine reports a snapshot *of the routed folder*. */
  isLoading: boolean;
  isRoot: boolean;
  error: SnapshotError | null;
  navigateTo(node: Uint8Array): void;
  /** Steps to the nearest ancestor; a no-op at the root. */
  navigateUp(): void;
}

export function useFolderNavigation(): FolderNavigation {
  const { nodeId } = useParams<{ nodeId: string }>();
  const navigate = useNavigate();
  const store = useSnapshotStore();
  const { view, error } = useSnapshot();

  const route = useMemo(() => folderRoute(nodeId), [nodeId]);

  useEffect(() => {
    if (route.kind === 'invalid') return;
    store.setFocus(route.kind === 'node' ? route.id : null);
  }, [route, store]);

  // A pull for the folder just left still lands under the new route, so the
  // view is only this route's answer once its folder matches.
  const listed =
    view !== null && sameNode(view.folder, route.kind === 'node' ? route.id : view.root)
      ? view
      : null;

  const navigateTo = useCallback(
    (node: Uint8Array) => {
      // The root is addressable as itself, but `/files` survives a root cut.
      navigate(folderPath(listed !== null && sameNode(node, listed.root) ? null : node));
    },
    [listed, navigate]
  );

  const navigateUp = useCallback(() => {
    const parent = listed?.ancestors[0];
    if (parent) navigateTo(parent.id);
  }, [listed, navigateTo]);

  const breadcrumbs = useMemo(
    () =>
      listed === null
        ? []
        : [...listed.ancestors].reverse().concat({ id: listed.folder, name: listed.folderName }),
    [listed]
  );

  const rows = useMemo(() => (listed === null ? [] : listingRows(listed.children)), [listed]);

  return {
    rows,
    folder: listed?.folder ?? null,
    breadcrumbs,
    isLoading: route.kind !== 'invalid' && listed === null && error === null,
    isRoot: listed !== null && sameNode(listed.folder, listed.root),
    error: route.kind === 'invalid' ? NOT_A_FOLDER : error,
    navigateTo,
    navigateUp,
  };
}
