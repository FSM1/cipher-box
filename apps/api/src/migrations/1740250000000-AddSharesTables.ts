import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Create the shares and share_keys tables for user-to-user sharing (Phase 14).
 *
 * These tables were previously only created via synchronize:true in dev/test.
 * This migration ensures they exist in staging/production where synchronize is off.
 *
 * Timestamp 1740250000000 must run BEFORE 1740300000000-SharesPartialUniqueIndex
 * which modifies the shares unique constraint.
 */
export class AddSharesTables1740250000000 implements MigrationInterface {
  name = 'AddSharesTables1740250000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // ──────────────────────────────────────────────
    // 1. shares
    // ──────────────────────────────────────────────
    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "shares" (
        "id"                    uuid NOT NULL DEFAULT uuid_generate_v4(),
        "sharer_id"             uuid NOT NULL,
        "recipient_id"          uuid NOT NULL,
        "item_type"             varchar(10) NOT NULL,
        "ipns_name"             varchar(255) NOT NULL,
        "item_name"             varchar(255) NOT NULL,
        "encrypted_key"         bytea NOT NULL,
        "hidden_by_recipient"   boolean NOT NULL DEFAULT false,
        "revoked_at"            TIMESTAMP,
        "created_at"            TIMESTAMP NOT NULL DEFAULT now(),
        "updated_at"            TIMESTAMP NOT NULL DEFAULT now(),
        CONSTRAINT "PK_shares" PRIMARY KEY ("id"),
        CONSTRAINT "FK_shares_sharer" FOREIGN KEY ("sharer_id")
          REFERENCES "users" ("id") ON DELETE CASCADE ON UPDATE NO ACTION,
        CONSTRAINT "FK_shares_recipient" FOREIGN KEY ("recipient_id")
          REFERENCES "users" ("id") ON DELETE CASCADE ON UPDATE NO ACTION
      )
    `);

    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "IDX_shares_sharer_id" ON "shares" ("sharer_id")`
    );
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "IDX_shares_recipient_id" ON "shares" ("recipient_id")`
    );
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "IDX_shares_ipns_name" ON "shares" ("ipns_name")`
    );

    // Initial absolute unique constraint — the next migration (1740300000000)
    // replaces this with a partial index (WHERE revoked_at IS NULL).
    await queryRunner.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS "UQ_shares_sharer_recipient_ipns"
      ON "shares" ("sharer_id", "recipient_id", "ipns_name")
    `);

    // ──────────────────────────────────────────────
    // 2. share_keys
    // ──────────────────────────────────────────────
    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "share_keys" (
        "id"              uuid NOT NULL DEFAULT uuid_generate_v4(),
        "share_id"        uuid NOT NULL,
        "key_type"        varchar(10) NOT NULL,
        "item_id"         varchar(255) NOT NULL,
        "encrypted_key"   bytea NOT NULL,
        "created_at"      TIMESTAMP NOT NULL DEFAULT now(),
        CONSTRAINT "PK_share_keys" PRIMARY KEY ("id"),
        CONSTRAINT "UQ_share_keys_share_type_item" UNIQUE ("share_id", "key_type", "item_id"),
        CONSTRAINT "FK_share_keys_share" FOREIGN KEY ("share_id")
          REFERENCES "shares" ("id") ON DELETE CASCADE ON UPDATE NO ACTION
      )
    `);

    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "IDX_share_keys_share_id" ON "share_keys" ("share_id")`
    );
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "IDX_share_keys_item_id" ON "share_keys" ("item_id")`
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // On staging/production this migration created both tables, so dropping them here is correct.
    // On fresh databases, FullSchema (1700000000000) created these tables and this migration
    // only added indexes. Reverting only this migration on a fresh DB will drop FullSchema-owned
    // tables; ensure FullSchema is also reverted to maintain consistency.
    await queryRunner.query(`DROP TABLE IF EXISTS "share_keys" CASCADE`);
    await queryRunner.query(`DROP TABLE IF EXISTS "shares" CASCADE`);
  }
}
