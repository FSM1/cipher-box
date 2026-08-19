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
      if (expected.type === 'lessThan') {
        return actual != null && (actual as Date | number) < (expected.value as Date | number);
      }
      if (expected.type === 'lessThanOrEqual') {
        return actual != null && (actual as Date | number) <= (expected.value as Date | number);
      }
      throw new Error(`FakeRepository: unsupported operator ${expected.type}`);
    }
    return actual === expected;
  });
}

/**
 * In-memory stand-in for the narrow TypeORM Repository surface the API
 * services use (findOne/save/insert/update/delete with plain equality + IsNull).
 */
export class FakeRepository<T extends { id: string }> {
  rows: T[] = [];

  private makeRow(partial: Partial<T>): T {
    return {
      createdAt: new Date(),
      ...partial,
      id: partial.id ?? randomUUID(),
    } as unknown as T;
  }

  async findOne(options: { where: Where }): Promise<T | null> {
    return this.rows.find((row) => matches(row as Record<string, unknown>, options.where)) ?? null;
  }

  async find(options: {
    where?: Where;
    order?: Record<string, 'ASC' | 'DESC'>;
    take?: number;
  }): Promise<T[]> {
    let result = options.where
      ? this.rows.filter((row) => matches(row as Record<string, unknown>, options.where as Where))
      : [...this.rows];
    const order = options.order;
    if (order) {
      const [[key, direction]] = Object.entries(order);
      result = [...result].sort((a, b) => {
        const av = (a as Record<string, unknown>)[key] as Date | number | string;
        const bv = (b as Record<string, unknown>)[key] as Date | number | string;
        const cmp = av < bv ? -1 : av > bv ? 1 : 0;
        return direction === 'DESC' ? -cmp : cmp;
      });
    }
    return options.take != null ? result.slice(0, options.take) : result;
  }

  async count(options: { where?: Where } = {}): Promise<number> {
    if (!options.where) {
      return this.rows.length;
    }
    return this.rows.filter((row) =>
      matches(row as Record<string, unknown>, options.where as Where)
    ).length;
  }

  async save(partial: Partial<T>): Promise<T> {
    if (partial.id) {
      const existing = this.rows.find((row) => row.id === partial.id);
      if (existing) {
        Object.assign(existing, partial);
        return existing;
      }
    }
    const row = this.makeRow(partial);
    this.rows.push(row);
    return row;
  }

  async insert(partials: Partial<T> | Partial<T>[]): Promise<void> {
    for (const partial of Array.isArray(partials) ? partials : [partials]) {
      this.rows.push(this.makeRow(partial));
    }
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
