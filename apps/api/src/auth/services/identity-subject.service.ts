import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { createHash } from 'node:crypto';
import { Repository } from 'typeorm';
import { Clock } from '../../common/clock';
import { IdentitySubject, IdentitySubjectKind } from '../entities/identity-subject.entity';

/**
 * Resolves a verified provider identity to its stable CipherBox subject id.
 *
 * Creates no `users` row: the account materializes at `POST /auth/login`
 * against the derived identity key, and nothing here knows that key yet.
 */
@Injectable()
export class IdentitySubjectService {
  constructor(
    @InjectRepository(IdentitySubject)
    private readonly subjects: Repository<IdentitySubject>,
    private readonly clock: Clock
  ) {}

  /**
   * The subject id for `identifier` under `kind`, minting one on first sight.
   *
   * Insert-then-read rather than check-then-insert: two concurrent first
   * logins for one identity both reach the insert, the unique index rejects
   * the loser, and the follow-up read returns the single winning row — so one
   * provider identity can never end up with two vaults.
   */
  async resolve(
    kind: IdentitySubjectKind,
    identifier: string,
    identifierDisplay: string | null
  ): Promise<string> {
    const identifierHash = hashIdentifier(identifier);
    const now = this.clock.now();

    const existing = await this.subjects.findOne({ where: { kind, identifierHash } });
    if (existing) {
      await this.subjects.update({ id: existing.id }, { lastUsedAt: now });
      return existing.id;
    }

    await this.subjects
      .createQueryBuilder()
      .insert()
      .into(IdentitySubject)
      .values({ kind, identifierHash, identifierDisplay, lastUsedAt: now })
      .orIgnore()
      .execute();

    const stored = await this.subjects.findOne({ where: { kind, identifierHash } });
    if (!stored) {
      throw new InternalServerErrorException('Identity subject could not be resolved');
    }
    return stored.id;
  }
}

/** SHA-256 hex of the canonical identifier; plaintext is never stored. */
export function hashIdentifier(identifier: string): string {
  return createHash('sha256').update(identifier).digest('hex');
}
