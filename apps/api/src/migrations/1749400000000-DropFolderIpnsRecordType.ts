import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Migration: Drop record_type column from folder_ipns table
 *
 * The record_type discriminator ('folder' vs 'file') was write-only metadata
 * the client volunteered to a zero-knowledge server. Nothing functional branched
 * on it (it fed only a single Prometheus gauge and two log strings), so it is
 * removed across the stack.
 *
 * Inverse of AddRecordTypeToFolderIpns1739800000000.
 */
export class DropFolderIpnsRecordType1749400000000 implements MigrationInterface {
  name = 'DropFolderIpnsRecordType1749400000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE "folder_ipns" DROP COLUMN IF EXISTS "record_type"
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Idempotent: IF NOT EXISTS prevents failure when synchronize:true already added the column
    await queryRunner.query(`
      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1 FROM information_schema.columns
          WHERE table_name = 'folder_ipns' AND column_name = 'record_type'
        ) THEN
          ALTER TABLE "folder_ipns"
          ADD COLUMN "record_type" varchar(10) NOT NULL DEFAULT 'folder';
        END IF;
      END $$;
    `);
  }
}
