import { MigrationInterface, QueryRunner } from 'typeorm';

export class DropVaultCryptoColumns1740700000000 implements MigrationInterface {
  name = 'DropVaultCryptoColumns1740700000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // All vaults are migrated to v2 blob format -- crypto material
    // lives in IPFS, not the database. Drop the dead columns.
    await queryRunner.query(`ALTER TABLE vaults DROP COLUMN IF EXISTS encrypted_root_folder_key`);
    await queryRunner.query(
      `ALTER TABLE vaults DROP COLUMN IF EXISTS encrypted_root_ipns_private_key`
    );
    await queryRunner.query(`ALTER TABLE vaults DROP COLUMN IF EXISTS migrated_at`);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE vaults ADD COLUMN IF NOT EXISTS encrypted_root_folder_key bytea NULL`
    );
    await queryRunner.query(
      `ALTER TABLE vaults ADD COLUMN IF NOT EXISTS encrypted_root_ipns_private_key bytea NULL`
    );
    await queryRunner.query(
      `ALTER TABLE vaults ADD COLUMN IF NOT EXISTS migrated_at TIMESTAMP NULL`
    );
  }
}
