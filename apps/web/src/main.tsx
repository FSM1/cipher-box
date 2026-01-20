import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Web3AuthProviderWrapper } from './lib/web3auth/provider';
import App from './App';
import './index.css';

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
    <Web3AuthProviderWrapper>
      <QueryClientProvider client={queryClient}>
        <App />
      </QueryClientProvider>
    </Web3AuthProviderWrapper>
  </StrictMode>
);
