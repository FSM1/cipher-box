import { MigrationInterface, QueryRunner } from 'typeorm';

export class DropIdentitySubjectDisplay1790640000000 implements MigrationInterface {
  name = 'DropIdentitySubjectDisplay1790640000000';

  // IF EXISTS: two runners that start together both reach this statement; the
  // second waits on the first's table lock and then finds nothing to drop.
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "identity_subjects" DROP COLUMN IF EXISTS "identifier_display"`
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "identity_subjects" ADD COLUMN IF NOT EXISTS "identifier_display" character varying(255)`
    );
  }
}
