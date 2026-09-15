import type { BinIndexHoldCheck, SettingsHoldCheck, SnapshotDescriptor } from '@cipherbox/client';
import { sameNode } from '../../lib/nodeId';
import { displayName } from '../../vault/displayName';

/** What the member has to change, in their words rather than the engine's. */
const SETTINGS_CAUSES: Record<SettingsHoldCheck, string> = {
  'byo-endpoint-invalid': 'the address of your own storage provider is not a usable web address',
  'byo-endpoint-insecure':
    'the address of your own storage provider is plain http to another machine, which would send your access token in the clear',
  'byo-endpoint-blocked': 'the address of your own storage provider is one this app may not call',
  'byo-credential-invalid':
    'the access token for your own storage provider carries characters a request cannot hold',
  'byo-provider-missing': 'your settings send bytes to your own storage provider and name none',
  'byo-no-external-ingress': 'the storage provider your settings name cannot take uploads',
};

/** Why the bin index did not resolve. Every one of these can clear on its own. */
const BIN_INDEX_CAUSES: Record<BinIndexHoldCheck, string> = {
  'unproven-first-run': 'nothing has served your bin to this device yet',
  suppressed: 'the record of your bin is being withheld',
  expired: 'the record of your bin is out of date and has not been renewed',
  'timed-out': 'the record of your bin did not arrive in time',
  'floor-unreadable': 'this device could not read what it holds the record of your bin to',
};

/**
 * The held queue head, when the member's own settings refused it or the owner's
 * bin index did not resolve for it. The over-quota hold is the upload panel's,
 * which renders the figure it carries. A hold clears, so the notice follows the
 * snapshot and goes when the hold does.
 */
export function QueueHoldNotice({ view }: { view: SnapshotDescriptor | null }) {
  const hold = view?.queueHold ?? null;
  if (view == null || hold === null || hold.reason === 'quota') return null;
  const text =
    hold.reason === 'settings'
      ? `${held(view, hold.node)} waits on your settings: ${SETTINGS_CAUSES[hold.check]}.`
      : `${held(view, hold.node)} waits on your bin: ${BIN_INDEX_CAUSES[hold.check]}.`;

  return (
    <div className="queue-hold-notice" role="status" data-testid="queue-hold-notice">
      <p className="queue-hold-notice-title">[!] a change is waiting</p>
      <ul className="queue-hold-notice-list">
        <li>{text}</li>
      </ul>
    </div>
  );
}

/** The held op's own node, named from the listing when this folder lists it. */
function held(view: SnapshotDescriptor, node: Uint8Array): string {
  const child = view.children.find((row) => sameNode(row.id, node));
  return child === undefined ? 'a change' : `"${displayName(child.name)}"`;
}
