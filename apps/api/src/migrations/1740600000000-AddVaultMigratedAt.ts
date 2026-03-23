import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Migration: Add vault migration tracking for v2 blob format
 *
 * Adds a migrated_at timestamp column to track per-user v2 blob migration.
 * Also makes the crypto columns (encrypted_root_folder_key, encrypted_root_ipns_private_key)
 * nullable so they can be NULLed after migration -- once a user migrates to v2,
 * the rootFolderKey lives in the IPFS vault blob instead of the database.
 */
export class AddVaultMigratedAt1740600000000 implements MigrationInterface {
  name = 'AddVaultMigratedAt1740600000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // Add migrated_at nullable timestamp for per-user v2 blob migration tracking
    await queryRunner.query(`
      ALTER TABLE vaults ADD COLUMN IF NOT EXISTS migrated_at TIMESTAMP NULL
    `);

    // Make crypto columns nullable so they can be NULLed after v2 migration
    // encrypted_root_folder_key: was NOT NULL, now nullable
    await queryRunner.query(`
      ALTER TABLE vaults ALTER COLUMN encrypted_root_folder_key DROP NOT NULL
    `);

    // encrypted_root_ipns_private_key: was NOT NULL, now nullable
    await queryRunner.query(`
      ALTER TABLE vaults ALTER COLUMN encrypted_root_ipns_private_key DROP NOT NULL
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TABLE vaults DROP COLUMN IF EXISTS migrated_at`);
    // Cannot safely re-add NOT NULL if NULLs exist
  }
}
