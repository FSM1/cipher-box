import { create } from 'zustand';

export type Notification = {
  id: string;
  type: 'info' | 'warning' | 'error';
  message: string;
  createdAt: number;
  action?: { label: string; onClick: () => void };
};

type NotificationState = {
  notifications: Notification[];
  addNotification: (
    type: Notification['type'],
    message: string,
    action?: Notification['action']
  ) => void;
  dismissNotification: (id: string) => void;
  clearNotifications: () => void;
};

export const useNotificationStore = create<NotificationState>((set) => ({
  notifications: [],

  addNotification: (type, message, action) =>
    set((state) => ({
      notifications: [
        ...state.notifications,
        {
          id: crypto.randomUUID(),
          type,
          message,
          createdAt: Date.now(),
          action,
        },
      ],
    })),

  dismissNotification: (id) =>
    set((state) => ({
      notifications: state.notifications.filter((n) => n.id !== id),
    })),

  clearNotifications: () => set({ notifications: [] }),
}));
