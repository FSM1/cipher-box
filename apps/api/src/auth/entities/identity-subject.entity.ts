import { Column, CreateDateColumn, Entity, Index, PrimaryGeneratedColumn } from 'typeorm';

/** The provider that vouched for the person (ADR 0008 D1/D2). */
export const IDENTITY_SUBJECT_KINDS = ['google', 'email', 'wallet'] as const;

export type IdentitySubjectKind = (typeof IDENTITY_SUBJECT_KINDS)[number];

/**
 * The stable CipherBox subject a verified provider identity maps to.
 *
 * The Core Kit derives its TSS key from `(verifier, verifierId)`, so this
 * row's `id` IS the vault: it rides the identity token's `sub`, is passed as
 * `verifierId`, and must never change for a given provider identity.
 *
 * Deliberately carries no `user_id`. The account still materializes at
 * `POST /auth/login`, keyed by the derived `publicKey` — this table's only job
 * is to yield a stable `verifierId`, so it cannot fork the account model. It is
 * also why several provider identities may point at one subject: that is what
 * linking a method means.
 */
@Entity('identity_subjects')
@Index('uq_identity_subjects_kind_identifier', ['kind', 'identifierHash'], { unique: true })
export class IdentitySubject {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'kind', type: 'varchar', length: 16 })
  kind: IdentitySubjectKind;

  /**
   * SHA-256 hex of the canonical provider identifier — Google's `sub`, the
   * normalized email, or the EIP-55 wallet address. Plaintext identifiers are
   * never stored, as in `auth_methods`.
   */
  @Column({ name: 'identifier_hash', type: 'varchar', length: 64 })
  identifierHash: string;

  /** Truncated human-readable identifier for account-settings display. */
  @Column({ name: 'identifier_display', type: 'varchar', length: 255, nullable: true })
  identifierDisplay: string | null;

  @Column({ name: 'last_used_at', type: 'timestamptz', nullable: true })
  lastUsedAt: Date | null;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;
}
