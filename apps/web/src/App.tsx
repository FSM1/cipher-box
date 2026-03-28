import { FaroErrorBoundary } from '@grafana/faro-react';
import { AppRoutes } from './routes';
import { ErrorFallback } from './components/ErrorFallback';
import './App.css';

function App() {
  return (
    <FaroErrorBoundary fallback={<ErrorFallback />}>
      <AppRoutes />
    </FaroErrorBoundary>
  );
}

export default App;
