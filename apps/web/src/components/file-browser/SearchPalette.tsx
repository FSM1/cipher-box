import { useState, useEffect, useRef, type ReactNode } from 'react';
import type { SearchResult } from '../../services/search-index.service';
import '../../styles/search-palette.css';

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/**
 * Return a terminal-aesthetic icon for a file or folder.
 * Uses Unicode characters that render well in JetBrains Mono.
 */
function getFileIcon(name: string, type: 'file' | 'folder'): string {
  if (type === 'folder') return '\u{1F5C0}'; // folder icon

  const lower = name.toLowerCase();
  const lastDot = lower.lastIndexOf('.');
  if (lastDot === -1) return '\u{1F5CE}'; // generic file

  const ext = lower.slice(lastDot);

  // Image
  if (['.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.bmp', '.ico', '.avif'].includes(ext)) {
    return '\u{1F5BC}'; // framed picture
  }
  // Video
  if (['.mp4', '.webm', '.mov', '.mkv'].includes(ext)) {
    return '\u{1F3AC}'; // clapper board
  }
  // Audio
  if (['.mp3', '.wav', '.ogg', '.m4a', '.flac'].includes(ext)) {
    return '\u{266B}'; // beamed eighth notes
  }
  // Document / PDF
  if (ext === '.pdf') {
    return '\u{1F4C4}'; // page facing up
  }
  // Code / text
  if (
    [
      '.ts',
      '.tsx',
      '.js',
      '.jsx',
      '.py',
      '.rs',
      '.go',
      '.java',
      '.c',
      '.cpp',
      '.h',
      '.html',
      '.css',
      '.json',
      '.yaml',
      '.yml',
      '.xml',
      '.toml',
      '.sh',
      '.md',
      '.txt',
    ].includes(ext)
  ) {
    return '\u{1F4DD}'; // memo
  }

  return '\u{1F5CE}'; // generic file
}

/**
 * Format a timestamp for display.
 * Within current year: "Feb 24". Older: "Feb 24, 2025". Falsy: "".
 */
function formatRelativeDate(timestamp: number): string {
  if (!timestamp) return '';

  const date = new Date(timestamp);
  const now = new Date();
  const months = [
    'Jan',
    'Feb',
    'Mar',
    'Apr',
    'May',
    'Jun',
    'Jul',
    'Aug',
    'Sep',
    'Oct',
    'Nov',
    'Dec',
  ];

  const month = months[date.getMonth()];
  const day = date.getDate();

  if (date.getFullYear() === now.getFullYear()) {
    return `${month} ${day}`;
  }
  return `${month} ${day}, ${date.getFullYear()}`;
}

/**
 * Highlight matching substrings in a name using MiniSearch match info.
 * Falls back to rendering the name without highlights if match info is unavailable.
 */
function highlightMatches(name: string, match: Record<string, string[]>): ReactNode {
  // Collect matched terms from the 'name' field
  const terms = match?.name ?? [];
  if (terms.length === 0) return name;

  // Build a set of character indices that are part of a match
  const matchedIndices = new Set<number>();
  const lower = name.toLowerCase();

  for (const term of terms) {
    const termLower = term.toLowerCase();
    let startPos = 0;
    // Find all occurrences of the term in the name
    while (startPos < lower.length) {
      const idx = lower.indexOf(termLower, startPos);
      if (idx === -1) break;
      for (let i = idx; i < idx + termLower.length; i++) {
        matchedIndices.add(i);
      }
      startPos = idx + 1;
    }
  }

  if (matchedIndices.size === 0) return name;

  // Build segments: consecutive matched/unmatched characters
  const segments: ReactNode[] = [];
  let i = 0;
  while (i < name.length) {
    const isMatch = matchedIndices.has(i);
    let j = i;
    while (j < name.length && matchedIndices.has(j) === isMatch) {
      j++;
    }
    const segment = name.slice(i, j);
    if (isMatch) {
      segments.push(<mark key={i}>{segment}</mark>);
    } else {
      segments.push(segment);
    }
    i = j;
  }

  return <>{segments}</>;
}

// ---------------------------------------------------------------------------
// SearchResultItem
// ---------------------------------------------------------------------------

function SearchResultItem({
  result,
  isSelected,
  onClick,
  onMouseEnter,
}: {
  result: SearchResult;
  isSelected: boolean;
  onClick: () => void;
  onMouseEnter: () => void;
}) {
  const icon = getFileIcon(result.name, result.type);
  const dateStr = formatRelativeDate(result.modifiedAt);
  const highlightedName = highlightMatches(result.name, result.match);

  return (
    <div
      className={`search-result-item ${isSelected ? 'selected' : ''}`}
      onClick={onClick}
      onMouseEnter={onMouseEnter}
      role="option"
      aria-selected={isSelected}
    >
      <span className={`search-result-icon ${isSelected ? 'icon-bright' : ''}`}>{icon}</span>
      <div className="search-result-info">
        <span className="search-result-name">{highlightedName}</span>
        <span className="search-result-path">{result.parentPath}</span>
      </div>
      {dateStr && <span className="search-result-date">{dateStr}</span>}
    </div>
  );
}

// ---------------------------------------------------------------------------
// SearchPalette
// ---------------------------------------------------------------------------

interface SearchPaletteProps {
  isOpen: boolean;
  query: string;
  onQueryChange: (q: string) => void;
  results: SearchResult[];
  resultCount: number;
  isBuilding: boolean;
  isIndexReady: boolean;
  onClose: () => void;
  onSelectResult: (result: SearchResult) => void;
}

/**
 * Command palette overlay for searching files and folders.
 *
 * Keyboard-first design: arrow keys navigate results, Enter opens,
 * Escape closes. Click outside backdrop also dismisses.
 *
 * Terminal aesthetic: JetBrains Mono, green on black, sharp corners.
 */
export function SearchPalette({
  isOpen,
  query,
  onQueryChange,
  results,
  resultCount,
  isBuilding,
  isIndexReady,
  onClose,
  onSelectResult,
}: SearchPaletteProps) {
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const resultsRef = useRef<HTMLDivElement>(null);
  const backdropRef = useRef<HTMLDivElement>(null);

  // Reset selection when results change
  useEffect(() => setSelectedIndex(0), [results]);

  // Focus input when opening
  useEffect(() => {
    if (isOpen) inputRef.current?.focus();
  }, [isOpen]);

  // Scroll selected item into view
  useEffect(() => {
    const container = resultsRef.current;
    if (!container) return;
    const selected = container.children[selectedIndex] as HTMLElement | undefined;
    selected?.scrollIntoView({ block: 'nearest' });
  }, [selectedIndex]);

  // Keyboard navigation
  const handleKeyDown = (e: React.KeyboardEvent) => {
    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        setSelectedIndex((i) => Math.min(i + 1, results.length - 1));
        break;
      case 'ArrowUp':
        e.preventDefault();
        setSelectedIndex((i) => Math.max(i - 1, 0));
        break;
      case 'Enter':
        e.preventDefault();
        if (results[selectedIndex]) {
          onSelectResult(results[selectedIndex]);
        }
        break;
      case 'Escape':
        e.preventDefault();
        onClose();
        break;
    }
  };

  // Click outside to close
  const handleBackdropClick = (e: React.MouseEvent) => {
    if (e.target === backdropRef.current) onClose();
  };

  if (!isOpen) return null;

  return (
    <div
      className="search-backdrop"
      ref={backdropRef}
      onClick={handleBackdropClick}
      role="dialog"
      aria-modal="true"
      aria-label="Search files"
    >
      <div className="search-palette" onKeyDown={handleKeyDown}>
        {/* Search input */}
        <div className="search-input-row">
          <span className="search-icon">&gt;_</span>
          <input
            ref={inputRef}
            className="search-input"
            type="text"
            placeholder="Search files..."
            value={query}
            onChange={(e) => onQueryChange(e.target.value)}
            autoComplete="off"
            spellCheck={false}
          />
          <span className="search-esc-hint">ESC</span>
        </div>

        {/* Results area */}
        <div className="search-results" ref={resultsRef} role="listbox" aria-label="Search results">
          {isBuilding && <div className="search-building">{'// building index...'}</div>}
          {!isBuilding && isIndexReady && query.trim() && results.length === 0 && (
            <div className="search-no-results">
              {"// no results for '"}
              {query}
              {"'"}
            </div>
          )}
          {results.map((result, index) => (
            <SearchResultItem
              key={result.id}
              result={result}
              isSelected={index === selectedIndex}
              onClick={() => onSelectResult(result)}
              onMouseEnter={() => setSelectedIndex(index)}
            />
          ))}
        </div>

        {/* Footer with keyboard hints and result count */}
        <div className="search-footer">
          <span className="search-footer-hints">
            <kbd>{'\u2191\u2193'}</kbd> navigate <kbd>{'\u21B5'}</kbd> open <kbd>esc</kbd> close
          </span>
          {resultCount > 0 && (
            <span className="search-footer-count">
              {'// '}
              {resultCount} result{resultCount !== 1 ? 's' : ''}
            </span>
          )}
        </div>
      </div>
    </div>
  );
}
