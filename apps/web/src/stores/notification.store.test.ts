import { afterEach, describe, expect, it } from 'vitest';
import { notificationStore } from './notification.store';

afterEach(() => notificationStore.clear());

describe('the notification store', () => {
  it('collapses a repeat of a warning that already stands', () => {
    notificationStore.warn('withheld:aa', 'a shared folder stopped serving updates');
    notificationStore.warn('withheld:aa', 'a shared folder stopped serving updates');

    expect(notificationStore.getState()).toHaveLength(1);
  });

  it('bounds what an event storm can accumulate', () => {
    for (let i = 0; i < 12; i += 1) notificationStore.warn(`abuse:${i}`, `refused ${i}`);

    const keys = notificationStore.getState().map((notice) => notice.key);
    expect(keys).toEqual(['abuse:7', 'abuse:8', 'abuse:9', 'abuse:10', 'abuse:11']);
  });

  it('raises the same key again once it was dismissed', () => {
    notificationStore.warn('withheld:aa', 'first');
    notificationStore.dismiss('withheld:aa');
    expect(notificationStore.getState()).toHaveLength(0);

    notificationStore.warn('withheld:aa', 'again');
    expect(notificationStore.getState()).toHaveLength(1);
  });

  it('notifies only on a change and publishes a stable snapshot', () => {
    let changes = 0;
    const drop = notificationStore.subscribe(() => (changes += 1));

    notificationStore.warn('abuse:x', 'refused');
    notificationStore.warn('abuse:x', 'refused');
    notificationStore.dismiss('abuse:missing');
    expect(changes).toBe(1);
    // `useSyncExternalStore` bails out on identity: a repeat read must match.
    expect(notificationStore.getState()).toBe(notificationStore.getState());

    drop();
    notificationStore.warn('abuse:y', 'refused');
    expect(changes).toBe(1);
  });
});
