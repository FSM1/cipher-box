import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Migration: Add signed_record column to folder_ipns table.
 *
 * Stores the canonical signed IPNS record bytes for the latest publish so
 * DB-cached resolves can return signature data for client-side verification.
 */
export class AddSignedRecordToFolderIpns1743200000000 implements MigrationInterface {
  name = 'AddSignedRecordToFolderIpns1743200000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1 FROM information_schema.columns
          WHERE table_name = 'folder_ipns' AND column_name = 'signed_record'
        ) THEN
          ALTER TABLE "folder_ipns"
          ADD COLUMN "signed_record" bytea;
        END IF;
      END $$;
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE "folder_ipns" DROP COLUMN IF EXISTS "signed_record"
    `);
  }
}
