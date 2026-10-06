import { useState, useSyncExternalStore } from 'react';
import { notificationStore, type Notice } from '../stores/notification.store';

/**
 * Standing warnings, dismissed by hand rather than on a timer: a trust warning
 * that expired unread would read as "nothing was wrong".
 */
export function NotificationToast() {
  const notices = useSyncExternalStore(notificationStore.subscribe, notificationStore.getState);
  const [running, setRunning] = useState<string | null>(null);

  if (notices.length === 0) return null;

  const act = (notice: Notice) => {
    if (notice.action === undefined) return;
    setRunning(notice.key);
    void notice.action
      .run()
      .catch(() => undefined)
      .finally(() => setRunning(null));
  };

  return (
    <div className="notification-toast" data-testid="notification-toast">
      {notices.map((notice) => (
        <div
          key={notice.key}
          className="notification-toast-item"
          role="alert"
          data-testid="notification-notice"
        >
          <span className="notification-toast-label" aria-hidden="true">
            [WARN]
          </span>
          <span className="notification-toast-message">{notice.message}</span>
          {notice.action !== undefined && (
            <button
              type="button"
              className="notification-toast-action"
              disabled={running !== null}
              onClick={() => act(notice)}
            >
              {running === notice.key ? '[working...]' : `[${notice.action.label}]`}
            </button>
          )}
          <button
            type="button"
            className="notification-toast-dismiss"
            aria-label="Dismiss warning"
            onClick={() => notificationStore.dismiss(notice.key)}
          >
            [x]
          </button>
        </div>
      ))}
    </div>
  );
}
