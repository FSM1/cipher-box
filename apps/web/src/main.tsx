// First import: Web3Auth's dependency graph reads the globals this installs.
import './polyfills';

import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter } from 'react-router-dom';
import { App } from './App';
import { EngineProvider } from './providers/EngineProvider';

const rootElement = document.getElementById('root');
if (!rootElement) {
  throw new Error('Root element #root not found');
}

const queryClient = new QueryClient();

createRoot(rootElement).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <EngineProvider>
        <BrowserRouter>
          <App />
        </BrowserRouter>
      </EngineProvider>
    </QueryClientProvider>
  </StrictMode>
);
