import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddNameInventoryAndPinnedCids1784566605863 implements MigrationInterface {
  name = 'AddNameInventoryAndPinnedCids1784566605863';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `CREATE TABLE "pinned_cids" ("id" uuid NOT NULL DEFAULT gen_random_uuid(), "account_id" uuid NOT NULL, "cid" character varying(256) NOT NULL, "size" bigint NOT NULL DEFAULT '0', "advisory" boolean NOT NULL DEFAULT false, "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), CONSTRAINT "PK_851abdeec6202c4b68375a2db0d" PRIMARY KEY ("id"))`
    );
    await queryRunner.query(`CREATE INDEX "idx_pinned_cids_cid" ON "pinned_cids" ("cid") `);
    await queryRunner.query(
      `CREATE UNIQUE INDEX "uq_pinned_cids_account_cid" ON "pinned_cids" ("account_id", "cid") `
    );
    await queryRunner.query(
      `CREATE TABLE "name_inventory" ("id" uuid NOT NULL DEFAULT gen_random_uuid(), "account_id" uuid NOT NULL, "ipns_name" character varying(128) NOT NULL, "head_cid" character varying(256), "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), CONSTRAINT "PK_dceb44e1d721492c6672d763bf7" PRIMARY KEY ("id"))`
    );
    await queryRunner.query(
      `CREATE INDEX "idx_name_inventory_ipns_name" ON "name_inventory" ("ipns_name") `
    );
    await queryRunner.query(
      `CREATE UNIQUE INDEX "uq_name_inventory_account_ipns" ON "name_inventory" ("account_id", "ipns_name") `
    );
    await queryRunner.query(
      `ALTER TABLE "pinned_cids" ADD CONSTRAINT "FK_a87e230cafef1df3885777f1e81" FOREIGN KEY ("account_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE NO ACTION`
    );
    await queryRunner.query(
      `ALTER TABLE "name_inventory" ADD CONSTRAINT "FK_a155da8994ed8c83c47a0cf876d" FOREIGN KEY ("account_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE NO ACTION`
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "name_inventory" DROP CONSTRAINT "FK_a155da8994ed8c83c47a0cf876d"`
    );
    await queryRunner.query(
      `ALTER TABLE "pinned_cids" DROP CONSTRAINT "FK_a87e230cafef1df3885777f1e81"`
    );
    await queryRunner.query(`DROP INDEX "public"."uq_name_inventory_account_ipns"`);
    await queryRunner.query(`DROP INDEX "public"."idx_name_inventory_ipns_name"`);
    await queryRunner.query(`DROP TABLE "name_inventory"`);
    await queryRunner.query(`DROP INDEX "public"."uq_pinned_cids_account_cid"`);
    await queryRunner.query(`DROP INDEX "public"."idx_pinned_cids_cid"`);
    await queryRunner.query(`DROP TABLE "pinned_cids"`);
  }
}
