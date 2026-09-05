import { render, screen } from '@testing-library/react';
import type { VaultStorageDescriptor } from '@cipherbox/client';
import { describe, expect, it } from 'vitest';
import { QuotaChrome } from './QuotaChrome';
import { FAKE_VAULT_STORAGE } from '../../test/authFakes';

const storage = (overrides: Partial<VaultStorageDescriptor> = {}): VaultStorageDescriptor => ({
  ...FAKE_VAULT_STORAGE,
  ...overrides,
});

describe('the quota chrome', () => {
  it('renders usage against the limit for a hosted vault', () => {
    render(<QuotaChrome storage={storage()} />);

    expect(screen.getByTestId('settings-quota').textContent).toContain('1 KB of 4 KB (25%)');
    expect(screen.queryByTestId('settings-quota-advisory')).toBeNull();
    expect(screen.queryByTestId('settings-pending-reclaim')).toBeNull();
  });

  it('marks the figure advisory where bytes land off the hosted store', () => {
    render(
      <QuotaChrome
        storage={storage({ quota: { usedBytes: 1024, limitBytes: 4096, advisory: true } })}
      />
    );

    expect(screen.getByTestId('settings-quota-advisory')).toBeTruthy();
  });

  it('names a debt the pass could not settle even where it prices at nothing', () => {
    render(
      <QuotaChrome
        storage={storage({
          pendingReclaimBytes: 0,
          reclaimStalls: [
            {
              node: new Uint8Array(16).fill(3),
              target: 'bafyDoomedRoot',
              reason: 'targetStillLive',
            },
          ],
        })}
      />
    );

    // The figure still reads zero; the stall is what says the ledger has not drained.
    expect(screen.getByTestId('settings-pending-reclaim').textContent).toBe('0 B');
    const stall = screen.getByTestId('settings-reclaim-stall');
    expect(stall.textContent).toContain('bafyDoomedRoot');
    expect(stall.textContent).toContain('still names this version');
  });

  it('says a figure the pass priced off one window of the ledger is a floor', () => {
    render(
      <QuotaChrome
        storage={storage({ pendingReclaimBytes: 4096, pendingReclaimIsPartial: true })}
      />
    );

    expect(screen.getByTestId('settings-pending-reclaim').textContent).toBe('at least 4 KB');
  });

  it('says the probe did not answer rather than rendering a figure it has not got', () => {
    render(<QuotaChrome storage={storage({ quota: null })} />);

    expect(screen.getByTestId('settings-quota').textContent).toContain('did not answer');
  });
});
