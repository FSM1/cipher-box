import { Column, Entity, Index, PrimaryColumn } from 'typeorm';

/**
 * An identity token a device registration has spent, kept until the token
 * expires: the token is a bearer, so a replay is refused by its `jti` here.
 */
@Entity('spent_identity_tokens')
export class SpentIdentityToken {
  @PrimaryColumn({
    name: 'token_id',
    type: 'uuid',
    primaryKeyConstraintName: 'pk_spent_identity_tokens',
  })
  tokenId: string;

  /** Indexed to drive the expired-row sweep that runs beside each spend. */
  @Index('idx_spent_identity_tokens_expires_at')
  @Column({ name: 'expires_at', type: 'timestamptz' })
  expiresAt: Date;
}
