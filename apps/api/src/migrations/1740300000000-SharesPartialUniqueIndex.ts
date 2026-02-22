import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Replace the absolute unique constraint on shares(sharer_id, recipient_id, ipns_name)
 * with a partial unique index that only applies to active (non-revoked) shares.
 *
 * This allows revoked share records (awaiting lazy key rotation) to coexist
 * with newly created active shares for the same sharer/recipient/item triple.
 */
export class SharesPartialUniqueIndex1740300000000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    // Drop the old absolute unique constraint (created by @Unique decorator or synchronize)
    // TypeORM names it UQ_<hash> -- use a safe approach: drop any unique index on these columns
    await queryRunner.query(`
      DO $$
      DECLARE idx_name text;
      BEGIN
        SELECT indexname INTO idx_name
        FROM pg_indexes
        WHERE tablename = 'shares'
          AND indexdef LIKE '%sharer_id%'
          AND indexdef LIKE '%recipient_id%'
          AND indexdef LIKE '%ipns_name%'
          AND indexdef LIKE '%UNIQUE%'
        LIMIT 1;

        IF idx_name IS NOT NULL THEN
          EXECUTE format('DROP INDEX IF EXISTS %I', idx_name);
        END IF;
      END $$;
    `);

    // Create partial unique index for active shares only
    await queryRunner.query(`
      CREATE UNIQUE INDEX "UQ_shares_active_triple"
      ON "shares" ("sharer_id", "recipient_id", "ipns_name")
      WHERE "revoked_at" IS NULL
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP INDEX IF EXISTS "UQ_shares_active_triple"`);

    // Restore the original absolute unique constraint
    await queryRunner.query(`
      CREATE UNIQUE INDEX "UQ_shares_sharer_recipient_ipns"
      ON "shares" ("sharer_id", "recipient_id", "ipns_name")
    `);
  }
}
