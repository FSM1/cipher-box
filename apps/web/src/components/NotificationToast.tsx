import { useSyncExternalStore } from 'react';
import { notificationStore } from '../stores/notification.store';

/**
 * Standing warnings, dismissed by hand rather than on a timer: a trust warning
 * that expired unread would read as "nothing was wrong".
 */
export function NotificationToast() {
  const notices = useSyncExternalStore(notificationStore.subscribe, notificationStore.getState);

  if (notices.length === 0) return null;

  return (
    <div className="notification-toast" data-testid="notification-toast">
      {notices.map((notice) => (
        <div
          key={notice.key}
          className="notification-toast-item"
          role="alert"
          data-testid="notification-notice"
          data-notice-class="warning"
        >
          <span className="notification-toast-label" aria-hidden="true">
            [WARN]
          </span>
          <span className="notification-toast-message">{notice.message}</span>
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
