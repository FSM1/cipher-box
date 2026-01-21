import type { Breadcrumb } from '../../hooks/useFolderNavigation';

type BreadcrumbsProps = {
  /** Breadcrumb trail from root to current folder */
  breadcrumbs: Breadcrumb[];
  /** Callback to navigate to a folder */
  onNavigate: (folderId: string) => void;
  /** Callback to navigate up to parent folder */
  onNavigateUp: () => void;
};

/**
 * Breadcrumb navigation component.
 *
 * Per CONTEXT.md: "simple back navigation with current folder name and back arrow"
 * Structure allows future dropdown-per-segment enhancement.
 *
 * Display:
 * - At root: just "My Vault" (no back arrow)
 * - In subfolder: back arrow + current folder name
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
export function Breadcrumbs({ breadcrumbs, onNavigateUp }: BreadcrumbsProps) {
  // Get current folder (last in breadcrumbs)
  const currentFolder = breadcrumbs[breadcrumbs.length - 1];

  // Check if we're at root (only one breadcrumb)
  const isAtRoot = breadcrumbs.length <= 1;

  if (!currentFolder) {
    return (
      <nav className="breadcrumbs" aria-label="Folder navigation">
        <span className="breadcrumbs-current">My Vault</span>
      </nav>
    );
  }

  return (
    <nav className="breadcrumbs" aria-label="Folder navigation">
      {/* Back button - hidden at root */}
      {!isAtRoot && (
        <button
          type="button"
          className="breadcrumbs-back"
          onClick={onNavigateUp}
          aria-label="Go back to parent folder"
        >
          <span className="breadcrumbs-back-icon" aria-hidden="true">
            &#8592;
          </span>
        </button>
      )}

      {/* Current folder name */}
      <span className="breadcrumbs-current" aria-current="location">
        {currentFolder.name}
      </span>
    </nav>
  );
}
