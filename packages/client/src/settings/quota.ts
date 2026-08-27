/**
 * What the storage pane renders, derived once from one `vaultStorage` read.
 *
 * The derivation lives here rather than in the UI so it is unit-tested: the web
 * app's own components are covered by the shell suite, not by assertions on
 * these rules.
 */

import type {
  ByoKind,
  PinMode,
  QuotaDescriptor,
  ReclaimStallReason,
  ReclaimStallDescriptor,
  VaultSettingsSummaryDescriptor,
  VaultStorageDescriptor,
} from '../worker/protocol.js';

/** What the quota chrome renders, derived once from one storage read. */
export interface QuotaChrome {
  /** `null` when the probe did not answer. */
  usage: { usedBytes: number; limitBytes: number; percent: number } | null;
  /** True when the figure is a hint rather than a ceiling. */
  advisory: boolean;
  /** Pending reclaim, or `null` once the ledger has drained. */
  pendingReclaimBytes: number | null;
  /** True when a debt the pass could not settle prices at nothing. */
  reclaimStalled: boolean;
  stalls: ReclaimStallDescriptor[];
}

export function quotaChrome(view: VaultStorageDescriptor): QuotaChrome {
  const stalls = view.reclaimStalls;
  const owed = view.pendingReclaimBytes;
  return {
    usage: usageOf(view.quota),
    // The engine decides this off the vaulted mode; re-deriving it from
    // `settings.pinMode` here would be a second copy of that rule.
    advisory: view.quota?.advisory ?? false,
    // A stall holds the figure on screen even at zero: that pairing is what
    // tells a drained ledger apart from one that never drains.
    pendingReclaimBytes: owed === 0 && stalls.length === 0 ? null : owed,
    reclaimStalled: stalls.length > 0,
    stalls,
  };
}

function usageOf(quota: QuotaDescriptor | null): QuotaChrome['usage'] {
  if (quota === null) return null;
  return {
    usedBytes: quota.usedBytes,
    limitBytes: quota.limitBytes,
    percent: quota.limitBytes === 0 ? 0 : Math.round((quota.usedBytes / quota.limitBytes) * 100),
  };
}

/** The settings-form fields a stored summary prefills. */
export function prefillFromSummary(summary: VaultSettingsSummaryDescriptor): {
  pinMode: PinMode;
  byoEndpoint: string;
  byoKind: ByoKind;
  keepLatestVersions: string;
  credentialStored: boolean;
} {
  return {
    pinMode: summary.pinMode,
    byoEndpoint: summary.byoEndpoint ?? '',
    byoKind: summary.byoKind ?? 'kubo',
    keepLatestVersions: summary.keepLatestVersions?.toString() ?? '',
    credentialStored: summary.byoCredentialStored,
  };
}

const UNITS = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'] as const;

/** Human-readable byte count, at most one decimal place. */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';

  const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), UNITS.length - 1);
  const value = bytes / 1024 ** exponent;
  const rounded = value % 1 === 0 ? value.toString() : value.toFixed(1);

  return `${rounded} ${UNITS[exponent]}`;
}

const STALL_REASONS: Record<ReclaimStallReason, string> = {
  nodeUnreadable: 'the owing node could not be read this pass',
  targetStillLive: 'the published record still names this version',
  targetUnexpandable: 'no source served the version this would unpin',
};

export function reclaimStallReason(reason: ReclaimStallReason): string {
  return STALL_REASONS[reason];
}
