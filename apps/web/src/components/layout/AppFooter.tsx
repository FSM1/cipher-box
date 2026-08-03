import { StatusIndicator } from './StatusIndicator';

/** Chrome: attribution, outbound links, and the staleness rung. */
export function AppFooter() {
  return (
    <footer className="app-footer" data-testid="app-footer">
      <div className="footer-left">
        <span className="footer-copyright">(c) 2026 CipherBox</span>
      </div>
      <div className="footer-center">
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
