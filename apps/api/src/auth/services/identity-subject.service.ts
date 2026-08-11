import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Clock } from '../../common/clock';
import { IdentitySubject, IdentitySubjectKind } from '../entities/identity-subject.entity';
import { IdentityService } from './identity.service';

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
    private readonly identityService: IdentityService,
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
    const identifierHash = this.identityService.hashIdentifier(identifier);
    const now = this.clock.now();

    const existing = await this.subjects.findOne({ where: { kind, identifierHash } });
    if (existing) {
      await this.subjects.update({ id: existing.id }, { lastUsedAt: now });
      return existing.id;
    }

    const inserted = await this.subjects
      .createQueryBuilder()
      .insert()
      .into(IdentitySubject)
      .values({ kind, identifierHash, identifierDisplay, lastUsedAt: now })
      .orIgnore()
      .returning('id')
      .execute();
    const mintedId = (inserted.raw as { id: string }[])[0]?.id;
    if (mintedId) return mintedId;

    // Lost the insert race, so the winner's row is the one that counts.
    const stored = await this.subjects.findOne({ where: { kind, identifierHash } });
    if (!stored) {
      throw new InternalServerErrorException('Identity subject could not be resolved');
    }
    return stored.id;
  }
}
