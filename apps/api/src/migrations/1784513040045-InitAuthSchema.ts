import { MigrationInterface, QueryRunner } from 'typeorm';

export class InitAuthSchema1784513040045 implements MigrationInterface {
  name = 'InitAuthSchema1784513040045';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `CREATE TABLE "auth_methods" ("id" uuid NOT NULL DEFAULT gen_random_uuid(), "user_id" uuid NOT NULL, "kind" character varying(16) NOT NULL, "identifier_hash" character varying(64) NOT NULL, "identifier_display" character varying(255), "last_used_at" TIMESTAMP WITH TIME ZONE, "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), CONSTRAINT "PK_17bba9bb4df315ca6603adea735" PRIMARY KEY ("id"))`
    );
    await queryRunner.query(
      `CREATE INDEX "idx_auth_methods_user_id" ON "auth_methods" ("user_id") `
    );
    await queryRunner.query(
      `CREATE UNIQUE INDEX "uq_auth_methods_kind_identifier" ON "auth_methods" ("kind", "identifier_hash") `
    );
    await queryRunner.query(
      `CREATE TABLE "refresh_tokens" ("id" uuid NOT NULL DEFAULT gen_random_uuid(), "user_id" uuid NOT NULL, "family_id" uuid NOT NULL, "token_hash" character varying(64) NOT NULL, "expires_at" TIMESTAMP WITH TIME ZONE NOT NULL, "used_at" TIMESTAMP WITH TIME ZONE, "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), CONSTRAINT "UQ_a7838d2ba25be1342091b6695f1" UNIQUE ("token_hash"), CONSTRAINT "PK_7d8bee0204106019488c4c50ffa" PRIMARY KEY ("id"))`
    );
    await queryRunner.query(
      `CREATE INDEX "idx_refresh_tokens_user_id" ON "refresh_tokens" ("user_id") `
    );
    await queryRunner.query(
      `CREATE INDEX "idx_refresh_tokens_family_id" ON "refresh_tokens" ("family_id") `
    );
    await queryRunner.query(
      `CREATE TABLE "users" ("id" uuid NOT NULL DEFAULT gen_random_uuid(), "public_key" character varying(130) NOT NULL, "quota_limit_override" bigint, "byo" boolean NOT NULL DEFAULT false, "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), "updated_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), CONSTRAINT "UQ_2c65307fa5c22f843f6c1089b18" UNIQUE ("public_key"), CONSTRAINT "PK_a3ffb1c0c8416b9fc6f907b7433" PRIMARY KEY ("id"))`
    );
    await queryRunner.query(
      `ALTER TABLE "auth_methods" ADD CONSTRAINT "FK_b8674f88fd00217ae9619f6c3e9" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE NO ACTION`
    );
    await queryRunner.query(
      `ALTER TABLE "refresh_tokens" ADD CONSTRAINT "FK_3ddc983c5f7bcf132fd8732c3f4" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE NO ACTION`
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "refresh_tokens" DROP CONSTRAINT "FK_3ddc983c5f7bcf132fd8732c3f4"`
    );
    await queryRunner.query(
      `ALTER TABLE "auth_methods" DROP CONSTRAINT "FK_b8674f88fd00217ae9619f6c3e9"`
    );
    await queryRunner.query(`DROP TABLE "users"`);
    await queryRunner.query(`DROP INDEX "public"."idx_refresh_tokens_family_id"`);
    await queryRunner.query(`DROP INDEX "public"."idx_refresh_tokens_user_id"`);
    await queryRunner.query(`DROP TABLE "refresh_tokens"`);
    await queryRunner.query(`DROP INDEX "public"."uq_auth_methods_kind_identifier"`);
    await queryRunner.query(`DROP INDEX "public"."idx_auth_methods_user_id"`);
    await queryRunner.query(`DROP TABLE "auth_methods"`);
  }
}
