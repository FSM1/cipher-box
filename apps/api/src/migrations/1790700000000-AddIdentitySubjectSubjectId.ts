import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddIdentitySubjectSubjectId1790700000000 implements MigrationInterface {
  name = 'AddIdentitySubjectSubjectId1790700000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `SELECT pg_advisory_xact_lock(hashtext('migration:AddIdentitySubjectSubjectId'))`
    );
    await queryRunner.query(
      `ALTER TABLE "identity_subjects" ADD COLUMN IF NOT EXISTS "subject_id" uuid`
    );
    // Every row before this migration is a first sight, so its subject is its own id.
    await queryRunner.query(
      `UPDATE "identity_subjects" SET "subject_id" = "id" WHERE "subject_id" IS NULL`
    );
    await queryRunner.query(
      `ALTER TABLE "identity_subjects" ALTER COLUMN "subject_id" SET NOT NULL`
    );
    // A wallet linked before this fix never opened the account; the member links it again.
    await queryRunner.query(
      `DELETE FROM "auth_methods" m WHERE m."kind" = 'wallet' AND NOT EXISTS (SELECT 1 FROM "identity_subjects" s WHERE s."kind" = m."kind" AND s."identifier_hash" = m."identifier_hash" AND s."id" <> s."subject_id")`
    );
    await queryRunner.query(
      `ALTER TABLE "identity_subjects" ADD CONSTRAINT "fk_identity_subjects_subject" FOREIGN KEY ("subject_id") REFERENCES "identity_subjects"("id") ON DELETE RESTRICT ON UPDATE NO ACTION`
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "identity_subjects" DROP CONSTRAINT IF EXISTS "fk_identity_subjects_subject"`
    );
    await queryRunner.query(`ALTER TABLE "identity_subjects" DROP COLUMN IF EXISTS "subject_id"`);
  }
}
