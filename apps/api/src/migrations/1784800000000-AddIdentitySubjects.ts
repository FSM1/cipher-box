import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddIdentitySubjects1784800000000 implements MigrationInterface {
  name = 'AddIdentitySubjects1784800000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `CREATE TABLE "identity_subjects" ("id" uuid NOT NULL DEFAULT gen_random_uuid(), "kind" character varying(16) NOT NULL, "identifier_hash" character varying(64) NOT NULL, "identifier_display" character varying(255), "last_used_at" TIMESTAMP WITH TIME ZONE, "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), CONSTRAINT "PK_737124c555f495beb736c066326" PRIMARY KEY ("id"))`
    );
    await queryRunner.query(
      `CREATE UNIQUE INDEX "uq_identity_subjects_kind_identifier" ON "identity_subjects" ("kind", "identifier_hash") `
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP INDEX "public"."uq_identity_subjects_kind_identifier"`);
    await queryRunner.query(`DROP TABLE "identity_subjects"`);
  }
}
