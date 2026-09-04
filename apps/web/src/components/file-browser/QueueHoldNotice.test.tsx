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
          settingsHold: { opId: 4n, node: NODE, check: 'byo-provider-missing' },
        })}
      />
    );

    const notice = screen.getByTestId('queue-hold-notice');
    expect(notice.textContent).toContain('"child-0" is waiting');
    expect(notice.textContent).toContain('your settings send bytes to your own storage provider');
  });

  it('names why the bin index did not resolve, and clears when the hold clears', () => {
    const { rerender } = render(
      <QueueHoldNotice
        view={listing({ binIndexHold: { opId: 5n, node: NODE, check: 'suppressed' } })}
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
          binIndexHold: { opId: 6n, node: new Uint8Array(16).fill(9), check: 'timed-out' },
        })}
      />
    );

    const notice = screen.getByTestId('queue-hold-notice');
    expect(notice.textContent).toContain('a change is waiting');
    expect(notice.textContent).not.toContain('child-0');
  });

  it('reports both holds at once', () => {
    render(
      <QueueHoldNotice
        view={listing({
          settingsHold: { opId: 4n, node: NODE, check: 'byo-endpoint-insecure' },
          binIndexHold: { opId: 5n, node: NODE, check: 'floor-unreadable' },
        })}
      />
    );

    expect(screen.getByTestId('queue-hold-notice').textContent).toContain('2 changes are waiting');
    expect(screen.getAllByRole('listitem')).toHaveLength(2);
  });
});
