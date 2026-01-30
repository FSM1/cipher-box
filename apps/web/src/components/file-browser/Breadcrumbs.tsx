import type { Breadcrumb } from '../../hooks/useFolderNavigation';

type BreadcrumbsProps = {
  /** Breadcrumb trail from root to current folder */
  breadcrumbs: Breadcrumb[];
  /** Callback to navigate to a folder (kept for potential future use) */
  onNavigate: (folderId: string) => void;
  /** Callback to navigate up to parent folder (kept for potential future use) */
  onNavigateUp: () => void;
};

/**
 * Breadcrumb navigation component - path format display.
 *
 * Per Phase 6.3 CONTEXT.md: Display path as ~/root/documents/projects format.
 * Parent navigation is now handled by [..] PARENT_DIR row in file list.
 *
 * Display:
 * - At root: ~/root
 * - In subfolder: ~/root/foldername/subfolder
 *
 * @example
 * ```tsx
 * function FileBrowser() {
 *   const { breadcrumbs, navigateTo, navigateUp } = useFolderNavigation();
 *
 *   return (
 *     <Breadcrumbs
 *       breadcrumbs={breadcrumbs}
 *       onNavigate={navigateTo}
 *       onNavigateUp={navigateUp}
 *     />
 *   );
 * }
 * ```
 */
export function Breadcrumbs({ breadcrumbs }: BreadcrumbsProps) {
  // Build path string from breadcrumbs
  // Convert folder names to lowercase for terminal aesthetic
  const pathString = '~/' + breadcrumbs.map((b) => b.name.toLowerCase()).join('/');

  return (
    <nav className="breadcrumb-path" aria-label="Current location" data-testid="breadcrumbs">
      <span className="breadcrumb-text">{pathString || '~/root'}</span>
    </nav>
  );
}
