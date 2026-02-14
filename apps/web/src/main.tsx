import './polyfills';
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
