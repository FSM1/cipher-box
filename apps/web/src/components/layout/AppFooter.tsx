import { StatusIndicator } from './StatusIndicator';

/**
 * App footer component.
 * Contains copyright, links, and connection status indicator.
 */
export function AppFooter() {
  return (
    <footer className="app-footer" data-testid="app-footer">
      <div className="footer-left">
        <span className="footer-copyright">(c) 2026 CipherBox</span>
      </div>
      <div className="footer-center">
        <a href="#" className="footer-link">
          [help]
        </a>
        <a href="#" className="footer-link">
          [privacy]
        </a>
        <a href="#" className="footer-link">
          [terms]
        </a>
        <a
          href="https://github.com/fsm1/cipher-box"
          className="footer-link"
          target="_blank"
          rel="noopener noreferrer"
        >
          [github]
        </a>
      </div>
      <div className="footer-right">
        <StatusIndicator />
      </div>
    </footer>
  );
}
