import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddRecordCache1784600557946 implements MigrationInterface {
  name = 'AddRecordCache1784600557946';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `CREATE TABLE "record_cache" ("ipns_name" character varying(128) NOT NULL, "record" bytea NOT NULL, "sequence" numeric(20,0) NOT NULL, "last_republished_at" TIMESTAMP WITH TIME ZONE, "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), CONSTRAINT "PK_49f183426ca65b21642fb75178c" PRIMARY KEY ("ipns_name"))`
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE "record_cache"`);
  }
}
