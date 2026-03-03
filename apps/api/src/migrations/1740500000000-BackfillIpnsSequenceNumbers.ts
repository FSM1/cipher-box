import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Migration: Backfill IPNS sequence numbers from '0' to '1'
 *
 * Before this fix, upsertFolderIpns created new entries with
 * sequenceNumber='0' while the client stored sequenceNumber=1n
 * (computing 0+1=1 after the first publish). Phase 16 added
 * conflict detection via expectedSequenceNumber, exposing this
 * off-by-one mismatch as 409 errors.
 *
 * This migration bumps non-root entries that have published content
 * (latestCid IS NOT NULL) from '0' to '1' to align with what
 * the client already stored.
 *
 * Root entries (created during vault init with latestCid=null) are
 * excluded because their first actual publish goes through the
 * UPDATE path which correctly increments.
 */
export class BackfillIpnsSequenceNumbers1740500000000 implements MigrationInterface {
  name = 'BackfillIpnsSequenceNumbers1740500000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      UPDATE "folder_ipns"
      SET "sequence_number" = '1'
      WHERE "sequence_number" = '0'
        AND "latest_cid" IS NOT NULL
        AND "is_root" = false
    `);
  }

  public async down(_queryRunner: QueryRunner): Promise<void> {
    // Not reversible — we can't distinguish which rows were backfilled
    // vs. which legitimately had sequence_number='1' before.
    // This is a data-only migration with no schema changes.
  }
}
