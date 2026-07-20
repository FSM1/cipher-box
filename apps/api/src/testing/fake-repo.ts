import { randomUUID } from 'node:crypto';
import { FindOperator } from 'typeorm';

type Where = Record<string, unknown>;

function matches(row: Record<string, unknown>, where: Where): boolean {
  return Object.entries(where).every(([key, expected]) => {
    const actual = row[key];
    if (expected instanceof FindOperator) {
      if (expected.type === 'isNull') {
        return actual === null || actual === undefined;
      }
      throw new Error(`FakeRepository: unsupported operator ${expected.type}`);
    }
    return actual === expected;
  });
}

/**
 * In-memory stand-in for the narrow TypeORM Repository surface the auth
 * services use (findOne/save/update/delete with plain equality + IsNull).
 */
export class FakeRepository<T extends { id: string }> {
  rows: T[] = [];

  async findOne(options: { where: Where }): Promise<T | null> {
    return this.rows.find((row) => matches(row as Record<string, unknown>, options.where)) ?? null;
  }

  async save(partial: Partial<T>): Promise<T> {
    if (partial.id) {
      const existing = this.rows.find((row) => row.id === partial.id);
      if (existing) {
        Object.assign(existing, partial);
        return existing;
      }
    }
    const row = {
      createdAt: new Date(),
      ...partial,
      id: partial.id ?? randomUUID(),
    } as unknown as T;
    this.rows.push(row);
    return row;
  }

  async update(criteria: Where, patch: Partial<T>): Promise<{ affected: number }> {
    let affected = 0;
    for (const row of this.rows) {
      if (matches(row as Record<string, unknown>, criteria)) {
        Object.assign(row, patch);
        affected += 1;
      }
    }
    return { affected };
  }

  async delete(criteria: Where): Promise<{ affected: number }> {
    const before = this.rows.length;
    this.rows = this.rows.filter((row) => !matches(row as Record<string, unknown>, criteria));
    return { affected: before - this.rows.length };
  }
}
