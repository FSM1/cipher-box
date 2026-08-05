// First import: Web3Auth's dependency graph reads the globals this installs.
import './polyfills';
import './index.css';
import './styles/login.css';
import './styles/layout.css';
import './styles/file-browser.css';
import './styles/upload.css';
import './styles/breadcrumbs.css';
import './styles/responsive.css';

import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter } from 'react-router-dom';
import { WagmiProvider } from 'wagmi';
import { App } from './App';
import { createCoreKitSession } from './auth/coreKit';
import { CoreKitProvider } from './auth/CoreKitProvider';
import { createEngineClient } from './engine/createEngineClient';
import { wagmiConfig } from './lib/wagmi';
import { EngineProvider } from './providers/EngineProvider';

const rootElement = document.getElementById('root');
if (!rootElement) {
  throw new Error('Root element #root not found');
}

const queryClient = new QueryClient();

createRoot(rootElement).render(
  <StrictMode>
    {/* wagmi drives its own react-query cache, so it wraps the QueryClient. The
        wallet is transient — reconnecting one on load would only surface stale
        connector errors on a page that needs a signature, not a session. */}
    <WagmiProvider config={wagmiConfig} reconnectOnMount={false}>
      <QueryClientProvider client={queryClient}>
        <EngineProvider createClient={createEngineClient}>
          <CoreKitProvider createSession={() => createCoreKitSession(import.meta.env)}>
            <BrowserRouter>
              <App />
            </BrowserRouter>
          </CoreKitProvider>
        </EngineProvider>
      </QueryClientProvider>
    </WagmiProvider>
  </StrictMode>
);
