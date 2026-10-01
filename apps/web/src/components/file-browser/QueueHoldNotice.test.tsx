import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { SnapshotDescriptor } from '@cipherbox/client';
import { QueueHoldNotice } from './QueueHoldNotice';
import { view } from '../../engine/testFakes';

const NODE = new Uint8Array(16).fill(1);

/** A snapshot listing one child, which is the node the holds below name. */
function listing(overrides: Partial<SnapshotDescriptor> = {}): SnapshotDescriptor {
  return { ...view(undefined, 'fresh', 1), ...overrides };
}

describe('the queue hold notice', () => {
  it('renders nothing while the drain holds nothing', () => {
    render(<QueueHoldNotice view={listing()} />);
    expect(screen.queryByTestId('queue-hold-notice')).toBeNull();
  });

  it('names the settings the member has to change, and the held item', () => {
    render(
      <QueueHoldNotice
        view={listing({
          queueHold: { reason: 'settings', opId: 4n, node: NODE, check: 'byo-provider-missing' },
        })}
      />
    );

    const notice = screen.getByTestId('queue-hold-notice');
    expect(notice.textContent).toContain('"child-0" waits on your settings');
    expect(notice.textContent).toContain('your settings send bytes to your own storage provider');
  });

  it('tells the member to enter the settings again after a stranded save', () => {
    render(
      <QueueHoldNotice
        view={listing({
          queueHold: { reason: 'settings', opId: 8n, node: NODE, check: 'stranded-mint' },
        })}
      />
    );

    const notice = screen.getByTestId('queue-hold-notice');
    expect(notice.textContent).toContain('"child-0" waits on your settings');
    expect(notice.textContent).toContain('the last settings save on this device did not finish');
    expect(notice.textContent).toContain(
      'enter your settings again, with your storage provider and its access token, and save them'
    );
  });

  it('names a rolled-back, a lapsed and an unreadable settings record each by its own cause', () => {
    const causes = {
      'revision-rolled-back': 'older than the one this device already used',
      expired: 'your settings record is out of date and was not renewed',
      unreadable: 'your settings record does not open on this device',
    } as const;
    for (const [check, cause] of Object.entries(causes)) {
      const { unmount } = render(
        <QueueHoldNotice
          view={listing({
            queueHold: {
              reason: 'settings',
              opId: 10n,
              node: NODE,
              check: check as keyof typeof causes,
            },
          })}
        />
      );
      const notice = screen.getByTestId('queue-hold-notice');
      expect(notice.textContent).toContain(cause);
      expect(notice.textContent).not.toContain('did not finish');
      expect(notice.textContent).toContain('save them');
      unmount();
    }
  });

  it('names why the bin index did not resolve, and clears when the hold clears', () => {
    const { rerender } = render(
      <QueueHoldNotice
        view={listing({
          queueHold: { reason: 'bin-index', opId: 5n, node: NODE, check: 'suppressed' },
        })}
      />
    );
    expect(screen.getByTestId('queue-hold-notice').textContent).toContain(
      'the record of your bin is being withheld'
    );

    rerender(<QueueHoldNotice view={listing()} />);
    expect(screen.queryByTestId('queue-hold-notice')).toBeNull();
  });

  it('reports a hold on a node this folder does not list without naming one', () => {
    render(
      <QueueHoldNotice
        view={listing({
          queueHold: {
            reason: 'bin-index',
            opId: 6n,
            node: new Uint8Array(16).fill(9),
            check: 'timed-out',
          },
        })}
      />
    );

    const notice = screen.getByTestId('queue-hold-notice');
    expect(notice.textContent).toContain('a change waits on your bin');
    expect(notice.textContent).not.toContain('child-0');
  });

  it('leaves the over-quota hold to the upload panel that renders its figure', () => {
    render(
      <QueueHoldNotice
        view={listing({
          queueHold: { reason: 'quota', opId: 7n, node: NODE, neededBytes: 900n },
        })}
      />
    );

    expect(screen.queryByTestId('queue-hold-notice')).toBeNull();
  });
});
