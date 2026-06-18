import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Decentralized IPNS model: key the folder_ipns cache by ipns_name ALONE
 * (one canonical record per name) instead of (user_id, ipns_name).
 *
 * Authority to update a name moves to record-signature verification (key
 * possession) in IpnsService.publishRecord, so a per-user row is no longer
 * meaningful — and per-user rows allowed a name to fork into divergent copies.
 * `user_id` is retained as a denormalized creator marker (listing, TEE
 * enrollment, cleanup).
 *
 * IPNS names are globally unique to an Ed25519 key, so duplicate ipns_name rows
 * across users are illegitimate (stale forks). We collapse any such duplicates to
 * the highest-sequence row before adding the unique constraint. Idempotent.
 */
export class IpnsCacheKeyedByName1749300000000 implements MigrationInterface {
  name = 'IpnsCacheKeyedByName1749300000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // 1. Collapse duplicate ipns_name rows: keep the most-advanced record
    //    (highest sequence_number, then most recently updated).
    await queryRunner.query(`
      DELETE FROM "folder_ipns" f
      USING (
        SELECT id, ROW_NUMBER() OVER (
          PARTITION BY ipns_name
          ORDER BY sequence_number DESC, updated_at DESC, created_at DESC
        ) AS rn
        FROM "folder_ipns"
      ) ranked
      WHERE f.id = ranked.id AND ranked.rn > 1
    `);

    // 2. Swap the unique constraint (user_id, ipns_name) -> (ipns_name).
    await queryRunner.query(
      `ALTER TABLE "folder_ipns" DROP CONSTRAINT IF EXISTS "UQ_folder_ipns_user_ipns"`
    );
    await queryRunner.query(`
      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1 FROM pg_constraint WHERE conname = 'UQ_folder_ipns_ipns_name'
        ) THEN
          ALTER TABLE "folder_ipns"
            ADD CONSTRAINT "UQ_folder_ipns_ipns_name" UNIQUE ("ipns_name");
        END IF;
      END $$;
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Note: deleted duplicate rows are not restored (they were stale forks).
    await queryRunner.query(
      `ALTER TABLE "folder_ipns" DROP CONSTRAINT IF EXISTS "UQ_folder_ipns_ipns_name"`
    );
    await queryRunner.query(`
      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1 FROM pg_constraint WHERE conname = 'UQ_folder_ipns_user_ipns'
        ) THEN
          ALTER TABLE "folder_ipns"
            ADD CONSTRAINT "UQ_folder_ipns_user_ipns" UNIQUE ("user_id", "ipns_name");
        END IF;
      END $$;
    `);
  }
}
