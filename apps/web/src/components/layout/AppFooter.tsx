/**
 * App footer component.
 * Contains copyright, links, and status indicator.
 */
export function AppFooter() {
  return (
    <footer className="app-footer" data-testid="app-footer">
      <div className="footer-left">
        <span className="footer-copyright">(c) 2026 CipherBox</span>
      </div>
      <div className="footer-center">{/* Links will be added in Task 2 */}</div>
      <div className="footer-right">{/* StatusIndicator will be added in Task 2 */}</div>
    </footer>
  );
}
