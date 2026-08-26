import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddAcceleratorTokens1787681144572 implements MigrationInterface {
  name = 'AddAcceleratorTokens1787681144572';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // This migration was renamed from AddGatewayTokens before it shipped, and
    // TypeORM keys applied migrations by class name — so a database that ran the
    // old name would keep its table, unswept, holding account-to-pseudonym rows.
    await queryRunner.query(`DROP TABLE IF EXISTS "gateway_tokens"`);
    await queryRunner.query(
      `CREATE TABLE "accelerator_tokens" ("id" uuid NOT NULL DEFAULT gen_random_uuid(), "user_id" uuid NOT NULL, "family_id" uuid NOT NULL, "token_hash" character varying(64) NOT NULL, "expires_at" TIMESTAMP WITH TIME ZONE NOT NULL, "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), CONSTRAINT "UQ_4039d0384665668627753051fff" UNIQUE ("token_hash"), CONSTRAINT "PK_93ddb4157f99b7c63dcca7a2529" PRIMARY KEY ("id"))`
    );
    await queryRunner.query(
      `CREATE INDEX "idx_accelerator_tokens_user_id" ON "accelerator_tokens" ("user_id") `
    );
    await queryRunner.query(
      `CREATE INDEX "idx_accelerator_tokens_expires_at" ON "accelerator_tokens" ("expires_at") `
    );
    await queryRunner.query(
      `ALTER TABLE "accelerator_tokens" ADD CONSTRAINT "FK_f60ccb81c4e9654af8cc7933ab2" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE NO ACTION`
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "accelerator_tokens" DROP CONSTRAINT "FK_f60ccb81c4e9654af8cc7933ab2"`
    );
    await queryRunner.query(`DROP INDEX "public"."idx_accelerator_tokens_expires_at"`);
    await queryRunner.query(`DROP INDEX "public"."idx_accelerator_tokens_user_id"`);
    await queryRunner.query(`DROP TABLE "accelerator_tokens"`);
  }
}
