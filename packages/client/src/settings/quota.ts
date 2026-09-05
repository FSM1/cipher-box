/** What the storage pane renders, derived once from one `vaultStorage` read. */

import type {
  ByoKind,
  PinMode,
  QuotaDescriptor,
  ReclaimStallReason,
  ReclaimStallDescriptor,
  SettingsOrigin,
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
  /** True when that figure is at least this much, rather than the whole debt. */
  pendingReclaimIsPartial: boolean;

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
    // A stall holds the figure on screen even at zero, and so does a pass that
    // priced only a window of the ledger: either pairing is what tells a
    // drained ledger apart from one this pass could not read to the end.
    pendingReclaimBytes:
      owed === 0 && stalls.length === 0 && !view.pendingReclaimIsPartial ? null : owed,
    pendingReclaimIsPartial: view.pendingReclaimIsPartial,
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
  binRetentionDays: number;
  credentialStored: boolean;
} {
  return {
    pinMode: summary.pinMode,
    byoEndpoint: summary.byoEndpoint ?? '',
    byoKind: summary.byoKind ?? 'kubo',
    keepLatestVersions: summary.keepLatestVersions?.toString() ?? '',
    binRetentionDays: summary.binRetentionDays,
    credentialStored: summary.byoCredentialStored,
  };
}

/** What one load's origin means for the form rendering it. */
export interface OriginNotice {
  /** Where the shown values came from, or `null` for the published record. */
  note: string | null;
  /**
   * True where nothing shown is the member's own choice, so a save publishes
   * documented defaults over a record this session never read.
   */
  unread: boolean;
}

const ORIGIN_NOTICES: Record<SettingsOrigin, OriginNotice> = {
  resolved: { note: null, unread: false },
  stale: {
    note: "this device's copy of your settings, not the record the vault published",
    unread: false,
  },
  // `defaults` covers a vault that never published a record and one whose
  // record did not resolve alike (`SettingsOrigin`), so the copy names both
  // rather than alarming a first run or reassuring a failed read.
  defaults: {
    note: 'no settings record loaded — this vault either never published one, or its record did not resolve. nothing on this form is your stored choice',
    unread: true,
  },
};

export function originNotice(origin: SettingsOrigin): OriginNotice {
  return ORIGIN_NOTICES[origin];
}

export type SettingsSaveVerdict = { ok: true } | { ok: false; problem: string };

/** The settings form as it stands, against the summary it was prefilled from. */
export interface SettingsSaveIntent {
  origin: SettingsOrigin;
  /** Whether the vault holds a provider bearer, which no read can show. */
  credentialStored: boolean;
  byoEndpoint: string;
  byoAccessToken: string;
  /** The member asked outright for the stored credential to go. */
  clearCredential: boolean;
  /** The member took on publishing over a record this session never read. */
  loadAcknowledged: boolean;
}

/**
 * Whether the form may be published as it stands. A save replaces the whole
 * record, so both refusals here are destructive edits the member did not ask
 * for: publishing defaults over an unread record, and blanking a bearer the
 * form cannot show back.
 */
export function settingsSaveVerdict(intent: SettingsSaveIntent): SettingsSaveVerdict {
  if (originNotice(intent.origin).unread && !intent.loadAcknowledged) {
    return {
      ok: false,
      problem:
        'no settings record loaded, so saving would publish these defaults over whatever the vault holds. take that on to save anyway.',
    };
  }
  if (
    intent.credentialStored &&
    intent.byoEndpoint.trim() !== '' &&
    intent.byoAccessToken === '' &&
    !intent.clearCredential
  ) {
    return {
      ok: false,
      problem:
        'a provider credential is stored and this field is blank, which would clear it. re-enter it, or clear it outright.',
    };
  }
  return { ok: true };
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
