/**
 * @cipherbox/sdk-core - Tree traversal utilities
 *
 * Pure tree algorithms extracted from apps/web/src/services/folder.service.ts.
 * Framework-agnostic -- no React/Zustand dependencies.
 */

/**
 * Minimal folder node interface for tree operations.
 * Matches the shape used by both web FolderNode and SDK FolderState.
 */
export type TreeNode = {
  id: string;
  parentId: string | null;
};

/**
 * Calculate the depth of a folder in the tree.
 *
 * @param folderId - The folder ID to calculate depth for (null = root = depth 0)
 * @param folders - Map of folder ID to TreeNode
 * @returns Depth from root (root = 0, immediate child = 1, etc.)
 */
export function getDepth(folderId: string | null, folders: Record<string, TreeNode>): number {
  if (!folderId) return 0;
  let depth = 0;
  let current: string | null = folderId;
  while (current) {
    const node: TreeNode | undefined = folders[current];
    if (!node || !node.parentId) break;
    depth++;
    current = node.parentId;
  }
  return depth;
}

/**
 * Calculate the maximum depth of a folder's subtree.
 *
 * @param folderId - Root folder of the subtree
 * @param folders - Map of folder ID to TreeNode
 * @returns Maximum depth relative to folderId (0 if no children)
 */
export function calculateSubtreeDepth(
  folderId: string,
  folders: Record<string, TreeNode>,
): number {
  let maxDepth = 0;
  for (const [id, node] of Object.entries(folders)) {
    if (id === folderId) continue;
    // Check if this node is a descendant of folderId
    let current: string | null = node.parentId;
    let depth = 0;
    while (current) {
      depth++;
      if (current === folderId) {
        maxDepth = Math.max(maxDepth, depth);
        break;
      }
      const parent = folders[current];
      current = parent?.parentId ?? null;
    }
  }
  return maxDepth;
}

/**
 * Check if a folder is a descendant of another folder.
 *
 * @param childId - Potential descendant folder ID
 * @param ancestorId - Potential ancestor folder ID
 * @param folders - Map of folder ID to TreeNode
 * @returns true if childId is inside ancestorId's subtree
 */
export function isDescendantOf(
  childId: string,
  ancestorId: string,
  folders: Record<string, TreeNode>,
): boolean {
  let current: string | null = childId;
  while (current) {
    const node: TreeNode | undefined = folders[current];
    if (!node) return false;
    if (node.parentId === ancestorId) return true;
    current = node.parentId;
  }
  return false;
}
