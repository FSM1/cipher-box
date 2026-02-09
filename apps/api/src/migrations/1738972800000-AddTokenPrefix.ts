import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddTokenPrefix1738972800000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    // Idempotent: column may already exist if FullSchema baseline ran first
    await queryRunner.query(
      `ALTER TABLE "refresh_tokens" ADD COLUMN IF NOT EXISTS "tokenPrefix" varchar(16)`
    );
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "IDX_refresh_token_prefix" ON "refresh_tokens" ("tokenPrefix")`
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP INDEX IF EXISTS "IDX_refresh_token_prefix"`);
    await queryRunner.query(`ALTER TABLE "refresh_tokens" DROP COLUMN IF EXISTS "tokenPrefix"`);
  }
}
