import type {
  BinIndexHoldCheck,
  QueueHoldDescriptor,
  SettingsHoldCheck,
  SnapshotDescriptor,
} from '@cipherbox/client';
import { sameNode } from '../../lib/nodeId';
import { displayName } from '../../vault/displayName';

const RESAVE =
  'enter your settings again, with your storage provider and its access token, and save them';

/** What the member has to change, in their words rather than the engine's. */
const SETTINGS_CAUSES: Record<SettingsHoldCheck, string> = {
  'byo-endpoint-invalid': 'the address of your own storage provider is not a usable web address',
  'byo-endpoint-insecure':
    'the address of your own storage provider is plain http to another machine, which would send your access token in the clear',
  'byo-endpoint-blocked': 'the address of your own storage provider is one this app may not call',
  'byo-credential-invalid':
    'the access token for your own storage provider carries characters a request cannot hold',
  'byo-credential-unresolved':
    'your settings keep a stored access token for your own storage provider and none was resolved. save your settings again',
  'byo-credential-not-stored':
    'your settings keep the stored access token for your own storage provider and this device holds none. enter the access token and save',
  'byo-credential-repointed':
    'your settings keep an access token stored for a different storage provider. enter the access token for this one and save',
  'byo-provider-missing': 'your settings send bytes to your own storage provider and name none',
  'byo-no-external-ingress': 'the storage provider your settings name cannot take uploads',
  'stranded-mint': `the last settings save on this device did not finish. ${RESAVE}`,
  'revision-rolled-back': `the settings record that arrived is older than the one this device already used. ${RESAVE}`,
  expired: `your settings record is out of date and was not renewed. ${RESAVE}`,
  unreadable: `your settings record does not open on this device. ${RESAVE}`,
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
 * The held queue head, when the member's own settings refused it, the owner's
 * bin index did not resolve for it, a delete's target record did not arrive, or
 * a record it builds on is at an envelope version this build does not read.
 * The over-quota hold is the upload panel's, which renders the figure it
 * carries. A hold clears, so the notice follows the snapshot and goes when the
 * hold does.
 */
export function QueueHoldNotice({ view }: { view: SnapshotDescriptor | null }) {
  const hold = view?.queueHold ?? null;
  if (view == null || hold === null || hold.reason === 'quota') return null;
  const text = holdText(view, hold);

  return (
    <div className="queue-hold-notice" role="status" data-testid="queue-hold-notice">
      <p className="queue-hold-notice-title">[!] a change is waiting</p>
      <ul className="queue-hold-notice-list">
        <li>{text}</li>
      </ul>
    </div>
  );
}

function holdText(
  view: SnapshotDescriptor,
  hold: Exclude<QueueHoldDescriptor, { reason: 'quota' }>
): string {
  switch (hold.reason) {
    case 'settings':
      return `${held(view, hold.node)} waits on your settings: ${SETTINGS_CAUSES[hold.check]}.`;
    case 'bin-index':
      return `${held(view, hold.node)} waits on your bin: ${BIN_INDEX_CAUSES[hold.check]}.`;
    case 'newer-release':
      return `${held(view, hold.node)} waits: another device runs a newer release. update this app.`;
    case 'delete-plane':
      return `the delete of ${held(view, hold.node)} waits: the record of the item did not arrive, so this device cannot yet tell whether it is shared.`;
  }
}

/** The held op's own node, named from the listing when this folder lists it. */
function held(view: SnapshotDescriptor, node: Uint8Array): string {
  const child = view.children.find((row) => sameNode(row.id, node));
  return child === undefined ? 'a change' : `"${displayName(child.name)}"`;
}
