import { InternalServerErrorException } from '@nestjs/common';
import { Repository } from 'typeorm';
import { describe, expect, it } from 'vitest';
import { FakeClock } from '../../testing/fakes';
import { IdentitySubject, IdentitySubjectKind } from '../entities/identity-subject.entity';
import { IdentityService } from './identity.service';
import { IdentitySubjectService } from './identity-subject.service';

interface Row {
  id: string;
  kind: IdentitySubjectKind;
  identifierHash: string;
  identifierDisplay: string | null;
  lastUsedAt: Date | null;
}

/**
 * `INSERT … ON CONFLICT DO NOTHING RETURNING id` under the unique index on
 * `(kind, identifier_hash)`: the winner gets its row back, an ignored conflict
 * returns none. Every read awaits, so concurrent callers interleave before any
 * of them inserts — which is what puts the losers on the fallback path.
 */
class FakeSubjectRepository {
  readonly rows: Row[] = [];
  ignoredInserts = 0;
  private nextId = 1;

  async findOne({
    where,
  }: {
    where: { kind: IdentitySubjectKind; identifierHash: string };
  }): Promise<Row | null> {
    await Promise.resolve();
    return (
      this.rows.find(
        (row) => row.kind === where.kind && row.identifierHash === where.identifierHash
      ) ?? null
    );
  }

  async update({ id }: { id: string }, patch: { lastUsedAt: Date }): Promise<void> {
    await Promise.resolve();
    const row = this.rows.find((candidate) => candidate.id === id);
    if (row) row.lastUsedAt = patch.lastUsedAt;
  }

  createQueryBuilder() {
    let pending: Omit<Row, 'id'>;
    const builder = {
      insert: () => builder,
      into: () => builder,
      values: (values: Omit<Row, 'id'>) => {
        pending = values;
        return builder;
      },
      orIgnore: () => builder,
      returning: () => builder,
      execute: async () => {
        await Promise.resolve();
        const conflict = this.rows.some(
          (row) => row.kind === pending.kind && row.identifierHash === pending.identifierHash
        );
        if (conflict) {
          this.ignoredInserts += 1;
          return { raw: [] };
        }
        const row: Row = { id: `subject-${this.nextId++}`, ...pending };
        this.rows.push(row);
        return { raw: [{ id: row.id }] };
      },
    };
    return builder;
  }
}

function subjectService(repository: FakeSubjectRepository) {
  return new IdentitySubjectService(
    repository as unknown as Repository<IdentitySubject>,
    new IdentityService(),
    new FakeClock()
  );
}

describe('IdentitySubjectService', () => {
  it('mints a subject on first sight and returns the inserted id', async () => {
    const repository = new FakeSubjectRepository();

    const id = await subjectService(repository).resolve('google', 'google-subject', 'me***@x.com');

    expect(repository.rows).toHaveLength(1);
    expect(id).toBe(repository.rows[0].id);
  });

  it('stores the identifier only as its hash, never in plaintext', async () => {
    const repository = new FakeSubjectRepository();

    await subjectService(repository).resolve('email', 'member@example.com', 'me***@example.com');

    expect(repository.rows[0].identifierHash).toBe(
      new IdentityService().hashIdentifier('member@example.com')
    );
    expect(JSON.stringify(repository.rows)).not.toContain('member@example.com');
  });

  it('returns the standing subject for an identity already seen', async () => {
    const repository = new FakeSubjectRepository();
    const service = subjectService(repository);

    const first = await service.resolve('wallet', '0xabc', '0xab***');
    const second = await service.resolve('wallet', '0xabc', '0xab***');

    expect(second).toBe(first);
    expect(repository.rows).toHaveLength(1);
  });

  it('keeps one identity from forking into two subjects across kinds', async () => {
    const repository = new FakeSubjectRepository();
    const service = subjectService(repository);

    const viaEmail = await service.resolve('email', 'member@example.com', 'me***@example.com');
    const viaGoogle = await service.resolve('google', 'member@example.com', 'me***@example.com');

    expect(viaGoogle).not.toBe(viaEmail);
    expect(repository.rows).toHaveLength(2);
  });

  // The `.returning('id')` fast path only covers the insert winner; every other
  // concurrent first login reaches the re-read, so it is asserted directly.
  it('mints one subject when the same identity logs in concurrently', async () => {
    const repository = new FakeSubjectRepository();
    const service = subjectService(repository);

    const resolved = await Promise.all(
      Array.from({ length: 8 }, () => service.resolve('google', 'google-subject', 'me***@x.com'))
    );

    expect(new Set(resolved).size).toBe(1);
    expect(repository.rows).toHaveLength(1);
    expect(repository.ignoredInserts).toBe(7);
  });

  it('refuses to invent a subject when the lost race leaves no winner to read', async () => {
    const repository = new FakeSubjectRepository();
    // A row that vanishes between the ignored insert and the re-read: the
    // fallback has nothing to return and must not fabricate an id.
    const builder = {
      insert: () => builder,
      into: () => builder,
      values: () => builder,
      orIgnore: () => builder,
      returning: () => builder,
      execute: () => Promise.resolve({ raw: [] }),
    };
    repository.createQueryBuilder = () => builder;

    await expect(
      subjectService(repository).resolve('google', 'google-subject', 'me***@x.com')
    ).rejects.toThrow(InternalServerErrorException);
  });
});
