import { describe, expect, it } from 'vitest';

import { formatBytes, prefillFromSummary, quotaChrome, reclaimStallReason } from './quota.js';
import type {
  PinMode,
  ReclaimStallDescriptor,
  VaultSettingsSummaryDescriptor,
  VaultStorageDescriptor,
} from '../worker/protocol.js';

function summary(overrides: Partial<VaultSettingsSummaryDescriptor> = {}) {
  return {
    pinMode: 'hosted',
    byoEndpoint: null,
    byoKind: null,
    byoCredentialStored: false,
    keepLatestVersions: null,
    origin: 'resolved',
    ...overrides,
  } satisfies VaultSettingsSummaryDescriptor;
}

const STALL: ReclaimStallDescriptor = {
  node: new Uint8Array(16).fill(3),
  target: 'bafyRootOfADoomedVersion',
  reason: 'targetStillLive',
};

/**
 * One storage read as the engine hands it over: `advisory` comes off the
 * engine's own vaulted mode, so the fixture derives it the way the engine does
 * rather than leaving the chrome free to re-derive it.
 */
function storage(overrides: {
  pinMode?: PinMode;
  quota?: VaultStorageDescriptor['quota'];
  pendingReclaimBytes?: number;
  reclaimStalls?: ReclaimStallDescriptor[];
}): VaultStorageDescriptor {
  const pinMode = overrides.pinMode ?? 'hosted';
  return {
    settings: summary({ pinMode }),
    quota:
      overrides.quota === undefined
        ? { usedBytes: 512, limitBytes: 2048, advisory: pinMode !== 'hosted' }
        : overrides.quota,
    pendingReclaimBytes: overrides.pendingReclaimBytes ?? 0,
    reclaimStalls: overrides.reclaimStalls ?? [],
  };
}

describe('quotaChrome', () => {
  it('renders a hosted vault its limit, as a limit', () => {
    const chrome = quotaChrome(storage({ pinMode: 'hosted' }));

    expect(chrome.usage).toEqual({ usedBytes: 512, limitBytes: 2048, percent: 25 });
    expect(chrome.advisory).toBe(false);
  });

  it('marks the figure advisory wherever bytes land off the hosted store', () => {
    for (const pinMode of ['external', 'dual'] satisfies PinMode[]) {
      expect(quotaChrome(storage({ pinMode })).advisory).toBe(true);
    }
  });

  it('shows nothing pending once the ledger has drained', () => {
    const chrome = quotaChrome(storage({ pendingReclaimBytes: 0, reclaimStalls: [] }));

    expect(chrome.pendingReclaimBytes).toBeNull();
    expect(chrome.reclaimStalled).toBe(false);
    expect(chrome.stalls).toEqual([]);
  });

  it('carries a pending figure the pass still owes', () => {
    expect(quotaChrome(storage({ pendingReclaimBytes: 4096 })).pendingReclaimBytes).toBe(4096);
  });

  // The point of the read: a debt priced at nothing leaves the figure reading
  // drained while the ledger never empties.
  it('still reports a stall when the debt it left prices at zero', () => {
    const chrome = quotaChrome(storage({ pendingReclaimBytes: 0, reclaimStalls: [STALL] }));

    expect(chrome.reclaimStalled).toBe(true);
    expect(chrome.pendingReclaimBytes).toBe(0);
    expect(chrome.stalls).toEqual([STALL]);
  });

  it('degrades rather than throwing when the quota probe did not answer', () => {
    const chrome = quotaChrome(storage({ pinMode: 'external', quota: null }));

    expect(chrome.usage).toBeNull();
    expect(chrome.advisory).toBe(false);
  });

  it('reports no percentage against a limit of nothing', () => {
    const chrome = quotaChrome(
      storage({ quota: { usedBytes: 900, limitBytes: 0, advisory: false } })
    );

    expect(chrome.usage).toEqual({ usedBytes: 900, limitBytes: 0, percent: 0 });
  });
});

describe('prefillFromSummary', () => {
  it('fills the form from the settings the vault published', () => {
    expect(
      prefillFromSummary(
        summary({
          pinMode: 'dual',
          byoEndpoint: 'https://kubo.example',
          byoKind: 'psa',
          byoCredentialStored: true,
          keepLatestVersions: 5,
        })
      )
    ).toEqual({
      pinMode: 'dual',
      byoEndpoint: 'https://kubo.example',
      byoKind: 'psa',
      keepLatestVersions: '5',
      credentialStored: true,
    });
  });

  it('reads a vault with no provider back as the blank the form starts at', () => {
    expect(prefillFromSummary(summary())).toEqual({
      pinMode: 'hosted',
      byoEndpoint: '',
      byoKind: 'kubo',
      keepLatestVersions: '',
      credentialStored: false,
    });
  });
});

describe('reclaimStallReason', () => {
  it('names each reason the engine can report', () => {
    expect(reclaimStallReason('nodeUnreadable')).toBe('the owing node could not be read this pass');
    expect(reclaimStallReason('targetStillLive')).toBe(
      'the published record still names this version'
    );
    expect(reclaimStallReason('targetUnexpandable')).toBe(
      'no source served the version this would unpin'
    );
  });
});

describe('formatBytes', () => {
  it('scales to the largest unit that leaves a readable figure', () => {
    expect(formatBytes(0)).toBe('0 B');
    expect(formatBytes(1024)).toBe('1 KB');
    expect(formatBytes(1536)).toBe('1.5 KB');
  });
});
