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
 * which blends the sender into a one-way digest — so the durable,
 * server-pivotable sender→recipient graph the blueprint forbids ("never a
 * durable graph, never key material") does not sit in the schema.
 *
 * That one-wayness is contingent on a CLIENT invariant: `idempotencyKey` must
 * be a high-entropy per-message random value. The sender set is enumerable
 * (account pubkeys, confirmable via the existence oracle), so a low-entropy
 * key (a counter, a deterministic derivation) would let a server-side observer
 * brute-force `sha256(senderPk:key)` and re-attribute a row's sender. A random
 * key makes the digest a genuine one-way commitment; a per-row salt is NOT an
 * option because it would break the (sender,key) determinism idempotency needs.
 * The engine's mailbox client is responsible for drawing the key from its RNG
 * seam (blueprint/engine.md); this boundary cannot enforce it.
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
