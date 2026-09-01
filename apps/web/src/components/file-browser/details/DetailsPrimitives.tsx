import { useEffect, useRef, useState, type ReactNode } from 'react';
import type { ListingRow } from '../../../vault/listing';
import { copyToClipboard } from './copy-clipboard';

/** How long the copy button stays acknowledged before it offers itself again. */
const ACKNOWLEDGED_MS = 2000;

/** Stands in for a field the snapshot has not projected. */
export const UNKNOWN = 'unknown';

export function DetailRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="details-row">
      <dt className="details-label">{label}</dt>
      <dd className="details-value">{children}</dd>
    </div>
  );
}

export function DetailSection({ label }: { label: string }) {
  return <div className="details-section">{`// ${label}`}</div>;
}

/** A value the snapshot did not carry; never rendered as `undefined`. */
export function DimValue({ children }: { children: ReactNode }) {
  return <span className="details-value--dim">{children}</span>;
}

/** What every node reports about itself, whatever its kind. */
export function NodeRows({ row }: { row: ListingRow }) {
  return (
    <>
      <DetailSection label="node" />
      <DetailRow label="name">
        <CopyableValue value={row.name} copyValue={row.storedName} label="name" />
      </DetailRow>
      <DetailRow label="type">
        <span className="details-badge">{row.icon}</span>
      </DetailRow>
      <DetailRow label="node id">
        <CopyableValue value={row.key} label="node id" />
      </DetailRow>
      <DetailRow label="modified">{row.modified}</DetailRow>
    </>
  );
}

/** What the op queue holds for this node. */
export function StateRows({ row }: { row: ListingRow }) {
  return (
    <>
      <DetailSection label="queue" />
      <DetailRow label="queued">
        {row.pending === 'none' ? <DimValue>nothing pending</DimValue> : `${row.pending} change`}
      </DetailRow>
      {row.deadLetter && <DetailRow label="dead letter">this change will not publish</DetailRow>}
    </>
  );
}

/** An identifying field, with a copy button that only confirms a real write. */
export function CopyableValue({
  value,
  copyValue = value,
  label,
}: {
  value: string;
  /** What the copy hands over, where the shown text is neutralised. */
  copyValue?: string;
  label: string;
}) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(
    () => () => {
      if (timer.current !== null) clearTimeout(timer.current);
    },
    []
  );

  const copy = async () => {
    if (!(await copyToClipboard(copyValue))) return;
    setCopied(true);
    if (timer.current !== null) clearTimeout(timer.current);
    timer.current = setTimeout(() => setCopied(false), ACKNOWLEDGED_MS);
  };

  return (
    <span className="details-copyable">
      <span className="details-copyable-text">{value}</span>
      <button
        type="button"
        className="details-copy"
        onClick={() => void copy()}
        aria-label={`copy ${label}`}
        aria-pressed={copied}
      >
        {copied ? 'ok' : 'cp'}
      </button>
    </span>
  );
}
