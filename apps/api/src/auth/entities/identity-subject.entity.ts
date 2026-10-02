import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';

/** The provider that vouched for the person (ADR 0008 D1/D2). */
export const IDENTITY_SUBJECT_KINDS = ['google', 'email', 'wallet'] as const;

export type IdentitySubjectKind = (typeof IDENTITY_SUBJECT_KINDS)[number];

/** Named so a link can tell a lost race with an exchange from every other fault. */
export const IDENTITY_SUBJECT_IDENTIFIER_UNIQUE = 'uq_identity_subjects_kind_identifier';

/**
 * The stable CipherBox subject a verified provider identity maps to.
 *
 * The Core Kit derives its TSS key from `(verifier, verifierId)`, so this
 * row's `subjectId` IS the vault: it rides the identity token's `sub`, is passed
 * as `verifierId`, and must never change for a given provider identity.
 *
 * Deliberately carries no `user_id`. The account still materializes at
 * `POST /auth/login`, keyed by the derived `publicKey` — this table's only job
 * is to yield a stable `verifierId`, so it cannot fork the account model.
 */
@Entity('identity_subjects')
@Index(IDENTITY_SUBJECT_IDENTIFIER_UNIQUE, ['kind', 'identifierHash'], { unique: true })
export class IdentitySubject {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  /**
   * The subject this identity opens. A first sight mints it equal to `id`; a
   * method link points another provider identity at an existing subject
   * (ADR 0039 D1), so several rows can carry one value.
   */
  @Column({ name: 'subject_id', type: 'uuid' })
  subjectId: string;

  /** A subject row other rows point at cannot be deleted from under them. */
  @ManyToOne(() => IdentitySubject, { onDelete: 'RESTRICT' })
  @JoinColumn({ name: 'subject_id', foreignKeyConstraintName: 'fk_identity_subjects_subject' })
  subject: IdentitySubject;

  @Column({ name: 'kind', type: 'varchar', length: 16 })
  kind: IdentitySubjectKind;

  /**
   * SHA-256 hex of the canonical provider identifier — Google's `sub`, the
   * normalized email, or the EIP-55 wallet address. The identifier is stored
   * only as this hash, with no display form.
   */
  @Column({ name: 'identifier_hash', type: 'varchar', length: 64 })
  identifierHash: string;

  @Column({ name: 'last_used_at', type: 'timestamptz', nullable: true })
  lastUsedAt: Date | null;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;
}
