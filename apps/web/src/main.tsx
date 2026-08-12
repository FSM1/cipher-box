// First import: Web3Auth's dependency graph reads the globals this installs.
import './polyfills';
import './index.css';
import './styles/login.css';
import './styles/layout.css';
import './styles/file-browser.css';
import './styles/upload.css';
import './styles/breadcrumbs.css';
import './styles/vault-actions.css';
import './styles/modal.css';
import './styles/dialogs.css';
import './styles/context-menu.css';
import './styles/responsive.css';

import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter } from 'react-router-dom';
import { WagmiProvider } from 'wagmi';
import { App } from './App';
import { createCoreKitSession, sealedCoreKitStore } from './auth/coreKit';
import { CoreKitProvider } from './auth/CoreKitProvider';
import { IdentityProvider } from './auth/IdentityProvider';
import { createIdentityExchange } from './auth/identityExchange';
import { apiBaseUrl, googleClientId } from './engine/config';
import { createEngineClient } from './engine/createEngineClient';
import { installIntrospection } from './engine/introspection';
import { wagmiConfig } from './lib/wagmi';
import { EngineProvider } from './providers/EngineProvider';

const rootElement = document.getElementById('root');
if (!rootElement) {
  throw new Error('Root element #root not found');
}

const queryClient = new QueryClient();

const identityExchange = createIdentityExchange(apiBaseUrl(import.meta.env));

createRoot(rootElement).render(
  <StrictMode>
    {/* wagmi drives its own react-query cache, so it wraps the QueryClient. The
        wallet is transient — reconnecting one on load would only surface stale
        connector errors on a page that needs a signature, not a session. */}
    <WagmiProvider config={wagmiConfig} reconnectOnMount={false}>
      <QueryClientProvider client={queryClient}>
        <EngineProvider
          createClient={(secrets) => installIntrospection(createEngineClient(secrets))}
        >
          <CoreKitProvider
            createSession={() => createCoreKitSession(import.meta.env, sealedCoreKitStore())}
          >
            <IdentityProvider
              exchange={identityExchange}
              googleClientId={googleClientId(import.meta.env)}
            >
              <BrowserRouter>
                <App />
              </BrowserRouter>
            </IdentityProvider>
          </CoreKitProvider>
        </EngineProvider>
      </QueryClientProvider>
    </WagmiProvider>
  </StrictMode>
);
