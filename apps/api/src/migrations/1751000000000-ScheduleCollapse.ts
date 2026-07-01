import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Schedule Collapse migration — TEE-03 / D-02.
 *
 * Drops the four signing-input columns from ipns_republish_schedule that are
 * now duplicated (and authoritative) on ipns_records:
 *   - encrypted_ipns_key (crypto-bearing duplicate — D-11 data-minimisation)
 *   - key_epoch
 *   - latest_cid
 *   - sequence_number
 *
 * After this migration the relay's getDueEntries query JOINs ipns_republish_schedule
 * to ipns_records on ipns_name to obtain signing inputs (wired in plan 67-07).
 * Adds IDX_ipns_republish_schedule_ipns_name to support that JOIN efficiently.
 *
 * Note: ipns_republish_schedule.ipns_name references ipns_records.ipns_name as a
 * plain varchar(255) — no SQL FK constraint exists (confirmed FK-map, Phase-66).
 * No FK drops are needed.
 *
 * down() deliberately throws — greenfield waiver (D-01, Phase-66).
 */
export class ScheduleCollapse1751000000000 implements MigrationInterface {
  name = 'ScheduleCollapse1751000000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // Drop the four duplicated signing-input columns (TEE-03 / D-02)
    await queryRunner.query(`
      ALTER TABLE "ipns_republish_schedule"
        DROP COLUMN IF EXISTS "encrypted_ipns_key",
        DROP COLUMN IF EXISTS "key_epoch",
        DROP COLUMN IF EXISTS "latest_cid",
        DROP COLUMN IF EXISTS "sequence_number"
    `);

    // Add JOIN index so getDueEntries can efficiently look up the ipns_records row
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "IDX_ipns_republish_schedule_ipns_name" ON "ipns_republish_schedule" ("ipns_name")`
    );
  }

  public async down(_queryRunner: QueryRunner): Promise<void> {
    throw new Error(
      'down() not implemented: greenfield migration under D-01 waiver (Phase-66). ' +
        'Staging DB is wiped on each deploy — no rollback target.'
    );
  }
}
