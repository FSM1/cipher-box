import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Migration: Make TEE fields nullable in folder_ipns table
 *
 * Phase 6 defers TEE integration to Phase 7+, so encrypted_ipns_private_key
 * and key_epoch columns need to be nullable to allow folder IPNS tracking
 * without requiring TEE encryption.
 *
 * This migration:
 * 1. Alters encrypted_ipns_private_key to allow NULL
 * 2. Alters key_epoch to allow NULL
 *
 * These columns were originally NOT NULL but are now nullable for Phase 6.
 * Existing data (if any) with NULL values will remain unchanged.
 */
export class MakeFolderIpnsTeeFieldsNullable1737520000000 implements MigrationInterface {
  name = 'MakeFolderIpnsTeeFieldsNullable1737520000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // Idempotent: columns may already be nullable if FullSchema baseline ran first.
    // DROP NOT NULL on an already-nullable column is a no-op in PostgreSQL.
    await queryRunner.query(`
      ALTER TABLE "folder_ipns"
      ALTER COLUMN "encrypted_ipns_private_key" DROP NOT NULL
    `);

    await queryRunner.query(`
      ALTER TABLE "folder_ipns"
      ALTER COLUMN "key_epoch" DROP NOT NULL
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Note: Reverting will fail if there are NULL values in these columns.
    // Consider cleaning up NULL values before running down migration.

    // Make key_epoch NOT NULL again
    await queryRunner.query(`
      ALTER TABLE "folder_ipns"
      ALTER COLUMN "key_epoch" SET NOT NULL
    `);

    // Make encrypted_ipns_private_key NOT NULL again
    await queryRunner.query(`
      ALTER TABLE "folder_ipns"
      ALTER COLUMN "encrypted_ipns_private_key" SET NOT NULL
    `);
  }
}
