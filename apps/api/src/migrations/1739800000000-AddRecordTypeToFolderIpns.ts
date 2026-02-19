import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Migration: Add record_type column to folder_ipns table
 *
 * Phase 12.6 introduces per-file IPNS metadata records. The folder_ipns
 * table now tracks both folder and file IPNS records, distinguished by
 * the record_type column.
 *
 * Default 'folder' ensures backward compatibility with existing rows.
 */
export class AddRecordTypeToFolderIpns1739800000000 implements MigrationInterface {
  name = 'AddRecordTypeToFolderIpns1739800000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
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

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE "folder_ipns" DROP COLUMN IF EXISTS "record_type"
    `);
  }
}
