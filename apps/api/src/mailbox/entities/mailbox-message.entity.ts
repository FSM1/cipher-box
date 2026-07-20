import { Column, Entity, Index, PrimaryGeneratedColumn } from 'typeorm';

/**
 * One sealed pointer parked for a recipient (blueprint/api.md, Mailbox).
 *
 * The mailbox is an integrity-untrusted, zero-knowledge transport: the row
 * holds an opaque HPKE-sealed blob the server never decodes, never logs, and
 * never verifies (payload signatures are checked client-side). Rows are
 * hard-deleted on ack and on TTL expiry — no crypto-bearing row outlives its
 * consumer (AGENTS.md; blueprint/api.md Data model).
 *
 * Privacy posture: the recipient identity publicKey is stored in the clear
 * (poll routing + the accepted exact-pubkey existence oracle needs it), but
 * the sender is NOT persisted as a separable column. Per-sender idempotency
 * rides `idempotencyScope` = sha256(`${senderPublicKey}:${idempotencyKey}`),
 * which blends the sender into a one-way digest — so there is no durable,
 * pivotable sender→recipient graph, only the transient edge the blueprint
 * accepts (Mailbox: "never a durable graph, never key material").
 */
@Entity('mailbox_messages')
@Index('uq_mailbox_recipient_idempotency', ['recipientPublicKey', 'idempotencyScope'], {
  unique: true,
})
@Index('idx_mailbox_recipient_received', ['recipientPublicKey', 'receivedAt'])
export class MailboxMessage {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  /** Canonical compressed secp256k1 recipient identity publicKey, lowercase hex. */
  @Column({ name: 'recipient_public_key', type: 'varchar', length: 130 })
  recipientPublicKey: string;

  /** sha256(`${senderPublicKey}:${idempotencyKey}`); scopes idempotent replay per sender. */
  @Column({ name: 'idempotency_scope', type: 'varchar', length: 64 })
  idempotencyScope: string;

  /** Opaque HPKE-sealed payload; never decoded or logged server-side. */
  @Column({ name: 'blob', type: 'bytea' })
  blob: Buffer;

  /** Post time from the injected clock; drives poll ordering and the 90-day TTL. */
  @Column({ name: 'received_at', type: 'timestamptz' })
  receivedAt: Date;
}
