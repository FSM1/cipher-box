import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Migration: Add public_key column to folder_ipns table.
 *
 * Stores the raw Ed25519 public key so network-resolved IPNS records can still
 * be verified when the published protobuf omits field 7.
 */
export class AddPublicKeyToFolderIpns1743300000000 implements MigrationInterface {
  name = 'AddPublicKeyToFolderIpns1743300000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1 FROM information_schema.columns
          WHERE table_name = 'folder_ipns' AND column_name = 'public_key'
        ) THEN
          ALTER TABLE "folder_ipns"
          ADD COLUMN "public_key" bytea;
        END IF;
      END $$;
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE "folder_ipns" DROP COLUMN IF EXISTS "public_key"
    `);
  }
}
