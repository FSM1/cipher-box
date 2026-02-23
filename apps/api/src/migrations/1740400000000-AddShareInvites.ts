import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Create the share_invites table for invite link sharing (Phase 15).
 *
 * Stores ephemeral invite records: token, wrapped key ciphertext, item reference,
 * sharer userId, expiry, status, and claimedBy.
 *
 * Timestamp 1740400000000 runs AFTER 1740300000000-SharesPartialUniqueIndex
 * (no dependency, but ordering is clear).
 */
export class AddShareInvites1740400000000 implements MigrationInterface {
  name = 'AddShareInvites1740400000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "share_invites" (
        "id"                    uuid NOT NULL DEFAULT uuid_generate_v4(),
        "token"                 varchar(44) NOT NULL,
        "sharer_id"             uuid NOT NULL,
        "item_type"             varchar(10) NOT NULL,
        "ipns_name"             varchar(255) NOT NULL,
        "item_name"             varchar(255) NOT NULL,
        "encrypted_key"         bytea NOT NULL,
        "encrypted_child_keys"  jsonb,
        "status"                varchar(20) NOT NULL DEFAULT 'active',
        "max_claims"            integer NOT NULL DEFAULT 1,
        "claim_count"           integer NOT NULL DEFAULT 0,
        "claimed_by"            uuid,
        "expires_at"            TIMESTAMP NOT NULL,
        "created_at"            TIMESTAMP NOT NULL DEFAULT now(),
        CONSTRAINT "PK_share_invites" PRIMARY KEY ("id"),
        CONSTRAINT "UQ_share_invites_token" UNIQUE ("token"),
        CONSTRAINT "FK_share_invites_sharer" FOREIGN KEY ("sharer_id")
          REFERENCES "users" ("id") ON DELETE CASCADE ON UPDATE NO ACTION,
        CONSTRAINT "FK_share_invites_claimed_by" FOREIGN KEY ("claimed_by")
          REFERENCES "users" ("id") ON DELETE SET NULL ON UPDATE NO ACTION
      )
    `);

    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "IDX_share_invites_sharer_id" ON "share_invites" ("sharer_id")`
    );
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "IDX_share_invites_expires_at" ON "share_invites" ("expires_at")`
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE IF EXISTS "share_invites" CASCADE`);
  }
}
