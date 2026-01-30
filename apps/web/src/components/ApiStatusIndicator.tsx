/**
 * @deprecated This component is replaced by StatusIndicator in components/layout/.
 * The status indicator is now in the app footer.
 * This file is kept for reference and will be removed in a future cleanup.
 */
import { useHealthControllerCheck } from '../api/health/health';

/**
 * API status indicator component.
 * Shows connection status to the backend API using the health endpoint.
 * Polls every 30 seconds and retries twice on failure.
 */
export function ApiStatusIndicator() {
  const { data, isLoading, isError } = useHealthControllerCheck({
    query: {
      refetchInterval: 30000,
      retry: 2,
      refetchOnWindowFocus: true,
    },
  });

  // Determine status based on query state
  const isOnline = !isLoading && !isError && data?.status === 'ok';
  const statusClass = isLoading ? 'loading' : isOnline ? 'online' : 'offline';
  const statusText = isLoading ? 'Checking...' : isOnline ? 'API Online' : 'API Offline';

  return (
    <div className="api-status">
      <span className={`status-dot ${statusClass}`} />
      <span>{statusText}</span>
    </div>
  );
}
