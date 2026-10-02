import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddUserIdentitySubject1790910095402 implements MigrationInterface {
  name = 'AddUserIdentitySubject1790910095402';

  // No backfill: an account binds at its next login that follows an exchange (ADR 0058).
  public async up(queryRunner: QueryRunner): Promise<void> {
    // Two runners that start together race the catalog; the transaction lock makes
    // the second wait and then find the column and its constraints.
    await queryRunner.query(
      `SELECT pg_advisory_xact_lock(hashtext('migration:AddUserIdentitySubject'))`
    );
    await queryRunner.query(
      `ALTER TABLE "users" ADD COLUMN IF NOT EXISTS "identity_subject_id" uuid`
    );
    await queryRunner.query(
      `DO $$ BEGIN
         IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'UQ_f13673f422536c547cdf4f564c8') THEN
           ALTER TABLE "users" ADD CONSTRAINT "UQ_f13673f422536c547cdf4f564c8" UNIQUE ("identity_subject_id");
         END IF;
         IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'FK_f13673f422536c547cdf4f564c8') THEN
           ALTER TABLE "users" ADD CONSTRAINT "FK_f13673f422536c547cdf4f564c8" FOREIGN KEY ("identity_subject_id") REFERENCES "identity_subjects"("id") ON DELETE NO ACTION ON UPDATE NO ACTION;
         END IF;
       END $$`
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "users" DROP CONSTRAINT IF EXISTS "FK_f13673f422536c547cdf4f564c8"`
    );
    await queryRunner.query(
      `ALTER TABLE "users" DROP CONSTRAINT IF EXISTS "UQ_f13673f422536c547cdf4f564c8"`
    );
    await queryRunner.query(`ALTER TABLE "users" DROP COLUMN IF EXISTS "identity_subject_id"`);
  }
}
