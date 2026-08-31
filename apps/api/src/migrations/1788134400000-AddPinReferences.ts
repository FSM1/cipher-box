import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddPinReferences1788134400000 implements MigrationInterface {
  name = 'AddPinReferences1788134400000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `CREATE TABLE "pin_references" ("id" uuid NOT NULL DEFAULT gen_random_uuid(), "account_id" uuid NOT NULL, "ipns_name" character varying(128) NOT NULL, "cid" character varying(256) NOT NULL, CONSTRAINT "PK_pin_references_id" PRIMARY KEY ("id"))`
    );
    await queryRunner.query(
      `CREATE UNIQUE INDEX "uq_pin_references_account_name_cid" ON "pin_references" ("account_id", "ipns_name", "cid") `
    );
    await queryRunner.query(
      `CREATE INDEX "idx_pin_references_account_cid" ON "pin_references" ("account_id", "cid") `
    );
    await queryRunner.query(
      `ALTER TABLE "pin_references" ADD CONSTRAINT "FK_e6a36b730270ed3027f77c94d17" FOREIGN KEY ("account_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE NO ACTION`
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "pin_references" DROP CONSTRAINT "FK_e6a36b730270ed3027f77c94d17"`
    );
    await queryRunner.query(`DROP INDEX "public"."idx_pin_references_account_cid"`);
    await queryRunner.query(`DROP INDEX "public"."uq_pin_references_account_name_cid"`);
    await queryRunner.query(`DROP TABLE "pin_references"`);
  }
}
