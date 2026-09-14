import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddRefreshTokenExpiresAtIndex1789358810000 implements MigrationInterface {
  name = 'AddRefreshTokenExpiresAtIndex1789358810000';

  // CREATE/DROP INDEX CONCURRENTLY cannot run inside a transaction, so TypeORM
  // must not wrap this migration in one — it builds the sweep-scan index without
  // taking a table lock that would block concurrent login and rotation writes.
  public transaction = false as const;

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `CREATE INDEX CONCURRENTLY "idx_refresh_tokens_expires_at" ON "refresh_tokens" ("expires_at") `
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP INDEX CONCURRENTLY "public"."idx_refresh_tokens_expires_at"`);
  }
}
