import { useEffect, useRef } from 'react';
import { useNotificationStore, type Notification } from '../stores/notification.store';

const AUTO_DISMISS_MS = 8000;

const typeColors: Record<Notification['type'], string> = {
  info: 'var(--color-green-primary)',
  warning: 'var(--color-warning)',
  error: 'var(--color-error)',
};

const labels: Record<Notification['type'], string> = {
  info: '[INFO]',
  warning: '[WARN]',
  error: '[ERR]',
};

export function NotificationToast() {
  const notifications = useNotificationStore((s) => s.notifications);
  const dismissNotification = useNotificationStore((s) => s.dismissNotification);
  const timersRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());

  useEffect(() => {
    const timers = timersRef.current;
    for (const n of notifications) {
      // Toasts carrying an action (e.g. D-06 exhaustion Retry) require an
      // explicit user decision and must never auto-dismiss.
      const skipAutoDismiss = !!n.action;
      if (!timers.has(n.id) && !skipAutoDismiss) {
        const timer = setTimeout(() => {
          dismissNotification(n.id);
          timers.delete(n.id);
        }, AUTO_DISMISS_MS);
        timers.set(n.id, timer);
      }
    }

    // Clean up timers for removed notifications
    for (const [id, timer] of timers) {
      if (!notifications.some((n) => n.id === id)) {
        clearTimeout(timer);
        timers.delete(id);
      }
    }
  }, [notifications, dismissNotification]);

  // Cleanup all timers on unmount
  useEffect(() => {
    const timers = timersRef.current;
    return () => {
      for (const timer of timers.values()) {
        clearTimeout(timer);
      }
      timers.clear();
    };
  }, []);

  if (notifications.length === 0) return null;

  return (
    <div
      style={{
        position: 'fixed',
        bottom: 16,
        right: 16,
        zIndex: 9999,
        display: 'flex',
        flexDirection: 'column',
        gap: 8,
        maxWidth: 400,
        pointerEvents: 'auto',
      }}
    >
      {notifications.map((n) => (
        <div
          key={n.id}
          role={n.type === 'warning' || n.type === 'error' ? 'alert' : 'status'}
          aria-live={n.type === 'warning' || n.type === 'error' ? 'assertive' : 'polite'}
          style={{
            background: 'rgb(0 0 0 / 92%)',
            border: `1px solid ${typeColors[n.type]}`,
            borderRadius: 2,
            padding: '8px 12px',
            fontFamily: 'var(--font-family-mono)',
            fontSize: 'var(--font-size-sm)',
            color: 'var(--color-text-primary)',
            display: 'flex',
            alignItems: 'flex-start',
            gap: 8,
          }}
        >
          <span style={{ color: typeColors[n.type], flexShrink: 0 }}>{labels[n.type]}</span>
          <span style={{ flex: 1 }}>{n.message}</span>
          {n.action && (
            <button
              onClick={n.action.onClick}
              className="notification-action-btn"
              style={{
                background: 'none',
                border: 'none',
                cursor: 'pointer',
                padding: 0,
                fontFamily: 'var(--font-family-mono)',
                fontSize: 'var(--font-size-sm)',
                flexShrink: 0,
              }}
            >
              {`[${n.action.label}]`}
            </button>
          )}
          <button
            onClick={() => dismissNotification(n.id)}
            style={{
              background: 'none',
              border: 'none',
              color: 'var(--color-text-muted)',
              cursor: 'pointer',
              padding: 0,
              fontFamily: 'var(--font-family-mono)',
              fontSize: 'var(--font-size-sm)',
              flexShrink: 0,
            }}
            aria-label="Dismiss notification"
          >
            [x]
          </button>
        </div>
      ))}
    </div>
  );
}
