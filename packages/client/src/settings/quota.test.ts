import { describe, expect, it } from 'vitest';

import {
  formatBytes,
  originNotice,
  prefillFromSummary,
  quotaChrome,
  reclaimStallReason,
  settingsSaveVerdict,
  type SettingsSaveIntent,
} from './quota.js';
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
    binRetentionDays: 30,
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

describe('originNotice', () => {
  it('leaves a resolved read unremarked: it is the member’s published record', () => {
    expect(originNotice('resolved')).toEqual({ note: null, unread: false });
  });

  it('names a stale read as this device’s copy, still the member’s own choice', () => {
    const notice = originNotice('stale');

    expect(notice.note).toMatch(/this device/);
    expect(notice.unread).toBe(false);
  });

  it('marks defaults as nobody’s choice, because nothing read the record', () => {
    const notice = originNotice('defaults');

    expect(notice.note).toMatch(/no settings record loaded/);
    expect(notice.unread).toBe(true);
  });
});

describe('settingsSaveVerdict', () => {
  const intent = (overrides: Partial<SettingsSaveIntent> = {}): SettingsSaveIntent => ({
    origin: 'resolved',
    credentialStored: false,
    byoEndpoint: '',
    byoAccessToken: '',
    clearCredential: false,
    loadAcknowledged: false,
    ...overrides,
  });

  const stored = (overrides: Partial<SettingsSaveIntent> = {}): SettingsSaveIntent =>
    intent({ credentialStored: true, byoEndpoint: 'https://kubo.example', ...overrides });

  it('takes a save off a record this session read', () => {
    expect(settingsSaveVerdict(intent())).toEqual({ ok: true });
  });

  // The regression the prefill introduced: every other field round-trips, so a
  // blank credential reads as "unchanged" while a save would publish it as gone.
  it('refuses a blank credential over one the vault still holds', () => {
    const verdict = settingsSaveVerdict(stored());

    expect(verdict.ok).toBe(false);
    expect(verdict.ok ? '' : verdict.problem).toMatch(/credential/);
  });

  it('takes the save once the member asks outright for the credential to go', () => {
    expect(settingsSaveVerdict(stored({ clearCredential: true }))).toEqual({ ok: true });
  });

  it('takes the save once a new credential is typed', () => {
    expect(settingsSaveVerdict(stored({ byoAccessToken: 'a fresh one' }))).toEqual({ ok: true });
  });

  it('lets a blank credential go with the provider it belonged to', () => {
    expect(settingsSaveVerdict(stored({ byoEndpoint: '  ' }))).toEqual({ ok: true });
  });

  it('refuses to publish defaults over a record nothing read', () => {
    const verdict = settingsSaveVerdict(intent({ origin: 'defaults' }));

    expect(verdict.ok).toBe(false);
    expect(verdict.ok ? '' : verdict.problem).toMatch(/no settings record loaded/);
  });

  it('publishes them once the member takes that on', () => {
    expect(settingsSaveVerdict(intent({ origin: 'defaults', loadAcknowledged: true }))).toEqual({
      ok: true,
    });
  });

  it('asks nothing extra of a stale read: it is still the member’s choice', () => {
    expect(settingsSaveVerdict(intent({ origin: 'stale' }))).toEqual({ ok: true });
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
