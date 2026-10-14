import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddSpentIdentityTokens1790640000001 implements MigrationInterface {
  name = 'AddSpentIdentityTokens1790640000001';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `CREATE TABLE IF NOT EXISTS "spent_identity_tokens" ("token_id" uuid NOT NULL, "expires_at" TIMESTAMP WITH TIME ZONE NOT NULL, CONSTRAINT "pk_spent_identity_tokens" PRIMARY KEY ("token_id"))`
    );
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_spent_identity_tokens_expires_at" ON "spent_identity_tokens" ("expires_at") `
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP INDEX IF EXISTS "public"."idx_spent_identity_tokens_expires_at"`);
    await queryRunner.query(`DROP TABLE IF EXISTS "spent_identity_tokens"`);
  }
}
