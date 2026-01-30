import { useHealthControllerCheck } from '../../api/health/health';

/**
 * Status indicator component.
 * Shows API connection status in the footer with a glowing dot and terminal-style text.
 */
export function StatusIndicator() {
  const { data, isLoading, isError } = useHealthControllerCheck({
    query: {
      refetchInterval: 30000,
      retry: 2,
      refetchOnWindowFocus: true,
    },
  });

  // Determine status based on query state
  const isConnected = !isLoading && !isError && data?.status === 'ok';

  let dotClass = 'status-indicator-dot';
  let statusText = '[CHECKING]';

  if (isLoading) {
    dotClass += ' status-indicator-dot--loading';
    statusText = '[CHECKING]';
  } else if (isConnected) {
    dotClass += ' status-indicator-dot--connected';
    statusText = '[CONNECTED]';
  } else {
    dotClass += ' status-indicator-dot--disconnected';
    statusText = '[DISCONNECTED]';
  }

  return (
    <div className="status-indicator" data-testid="status-indicator">
      <span className={dotClass} />
      <span className="status-indicator-text">{statusText}</span>
    </div>
  );
}
