import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddAcceleratorTokens1787681144572 implements MigrationInterface {
  name = 'AddAcceleratorTokens1787681144572';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `CREATE TABLE "accelerator_tokens" ("id" uuid NOT NULL DEFAULT gen_random_uuid(), "user_id" uuid NOT NULL, "family_id" uuid NOT NULL, "token_hash" character varying(64) NOT NULL, "expires_at" TIMESTAMP WITH TIME ZONE NOT NULL, "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), CONSTRAINT "UQ_9a7d64c79ba834346582a212254" UNIQUE ("token_hash"), CONSTRAINT "PK_f53d1ffc86a74fe2e24bfbfc148" PRIMARY KEY ("id"))`
    );
    await queryRunner.query(
      `CREATE INDEX "idx_accelerator_tokens_user_id" ON "accelerator_tokens" ("user_id") `
    );
    await queryRunner.query(
      `CREATE INDEX "idx_accelerator_tokens_expires_at" ON "accelerator_tokens" ("expires_at") `
    );
    await queryRunner.query(
      `ALTER TABLE "accelerator_tokens" ADD CONSTRAINT "FK_7bebe1dc55a6f2ea7d6c054e3fa" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE NO ACTION`
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "accelerator_tokens" DROP CONSTRAINT "FK_7bebe1dc55a6f2ea7d6c054e3fa"`
    );
    await queryRunner.query(`DROP INDEX "public"."idx_accelerator_tokens_expires_at"`);
    await queryRunner.query(`DROP INDEX "public"."idx_accelerator_tokens_user_id"`);
    await queryRunner.query(`DROP TABLE "accelerator_tokens"`);
  }
}
