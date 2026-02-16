import './polyfills';

// DEBUG: Error capture for UAT - captures first 20 errors to window.__errorLog
if (import.meta.env.DEV) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const w = window as any;
  w.__errorLog = [];
  w.__errorCount = 0;
  const origError = console.error;
  console.error = function (...args: unknown[]) {
    w.__errorCount++;
    if (w.__errorLog.length < 20) {
      w.__errorLog.push({
        type: 'console.error',
        count: w.__errorCount,
        msg: args
          .map((a) => (typeof a === 'string' ? a.substring(0, 300) : String(a).substring(0, 300)))
          .join(' '),
        time: Date.now(),
      });
    }
    // After 100 errors, stop logging to prevent browser crash
    if (w.__errorCount <= 100) {
      origError.apply(console, args);
    }
  };
}

import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { WagmiSetup } from './lib/wagmi/provider';
import { CoreKitProvider } from './lib/web3auth/core-kit-provider';
import App from './App';
import './index.css';

// Expose Zustand stores for E2E test state injection (dev mode only)
if (import.meta.env.DEV) {
  import('./stores/auth.store').then(({ useAuthStore }) => {
    import('./stores/vault.store').then(({ useVaultStore }) => {
      import('./stores/folder.store').then(({ useFolderStore }) => {
        import('./stores/sync.store').then(({ useSyncStore }) => {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          (window as any).__ZUSTAND_STORES = {
            auth: useAuthStore,
            vault: useVaultStore,
            folder: useFolderStore,
            sync: useSyncStore,
          };
        });
      });
    });
  });
}

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 1000 * 60 * 5, // 5 minutes
      retry: 1,
    },
  },
});

const rootElement = document.getElementById('root');
if (!rootElement) throw new Error('Root element not found');

createRoot(rootElement).render(
  <StrictMode>
    <WagmiSetup>
      <CoreKitProvider>
        <QueryClientProvider client={queryClient}>
          <App />
        </QueryClientProvider>
      </CoreKitProvider>
    </WagmiSetup>
  </StrictMode>
);
