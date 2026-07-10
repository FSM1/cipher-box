import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * API Schema Cutover migration — brings schema to node/v3 model.
 *
 * Drop-recreate strategy (D-01 greenfield waiver — staging DB wiped on each deploy):
 *   1. DROP share_keys (removes FK dependency before shares is dropped)
 *   2. DROP + CREATE shares (encrypted-key schema; D-06/D-09/D-11)
 *   3. DROP + CREATE share_invites (slimmed; single ephemeral-wrapped readKey; D-05)
 *   4. DROP folder_ipns (no external SQL FKs confirmed by FK-map research)
 *   5. CREATE ipns_records (no public_key; adds tombstoned_at + generation; D-02/D-10)
 *
 * FK-map result: ipns_republish_schedule/shares/vaults reference ipns_name as a plain
 * varchar(255) — no SQL FK constraints point at folder_ipns. No cascade FK drops needed.
 *
 * down() deliberately throws — greenfield waiver (D-01).
 */
export class ApiSchemaCutover1750000000000 implements MigrationInterface {
  name = 'ApiSchemaCutover1750000000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // ──────────────────────────────────────────────────────────────────────────
    // Step 1: Drop share_keys
    // Removes FK_share_keys_share before shares is dropped. share_keys had a FK
    // to shares(id) ON DELETE CASCADE, so DROP CASCADE handles it either way, but
    // explicit ordering is clearer.
    // ──────────────────────────────────────────────────────────────────────────
    await queryRunner.query(`DROP TABLE IF EXISTS "share_keys" CASCADE`);

    // ──────────────────────────────────────────────────────────────────────────
    // Step 2: Drop and recreate shares (encrypted-key schema)
    //
    // Target columns (from share.entity.ts — 66-03):
    //   id, sharer_id, recipient_id, encrypted_read_key, encrypted_write_key,
    //   root_node_id, share_root_ipns_name, root_generation, item_name_encrypted,
    //   hidden_by_recipient, created_at, updated_at
    //
    // Unique: (sharer_id, recipient_id, root_node_id) — plain, no partial index (D-11)
    // FKs: sharer_id → users(id), recipient_id → users(id), both ON DELETE CASCADE
    // ──────────────────────────────────────────────────────────────────────────
    await queryRunner.query(`DROP TABLE IF EXISTS "shares" CASCADE`);

    await queryRunner.query(`
      CREATE TABLE "shares" (
        "id"                   uuid NOT NULL DEFAULT uuid_generate_v4(),
        "sharer_id"            uuid NOT NULL,
        "recipient_id"         uuid NOT NULL,
        "encrypted_read_key"   bytea NOT NULL,
        "encrypted_write_key"  bytea,
        "root_node_id"         uuid NOT NULL,
        "share_root_ipns_name" varchar(255) NOT NULL,
        "root_generation"      bigint NOT NULL DEFAULT 0,
        "item_name_encrypted"  bytea,
        "hidden_by_recipient"  boolean NOT NULL DEFAULT false,
        "created_at"           TIMESTAMP NOT NULL DEFAULT now(),
        "updated_at"           TIMESTAMP NOT NULL DEFAULT now(),
        CONSTRAINT "PK_shares" PRIMARY KEY ("id"),
        CONSTRAINT "UQ_shares_sharer_recipient_node" UNIQUE ("sharer_id", "recipient_id", "root_node_id")
      )
    `);

    await queryRunner.query(`
      ALTER TABLE "shares"
      ADD CONSTRAINT "FK_shares_sharer" FOREIGN KEY ("sharer_id")
        REFERENCES "users" ("id") ON DELETE CASCADE ON UPDATE NO ACTION
    `);

    await queryRunner.query(`
      ALTER TABLE "shares"
      ADD CONSTRAINT "FK_shares_recipient" FOREIGN KEY ("recipient_id")
        REFERENCES "users" ("id") ON DELETE CASCADE ON UPDATE NO ACTION
    `);

    await queryRunner.query(`CREATE INDEX "IDX_shares_sharer_id" ON "shares" ("sharer_id")`);
    await queryRunner.query(`CREATE INDEX "IDX_shares_recipient_id" ON "shares" ("recipient_id")`);
    // Composite index for the (sharer_id, share_root_ipns_name) access path used by
    // revokeForItems' bulk DELETE (SC#5) and the D-01 ownership-scoped share lookups.
    await queryRunner.query(
      `CREATE INDEX "IDX_shares_sharer_root" ON "shares" ("sharer_id", "share_root_ipns_name")`
    );

    // ──────────────────────────────────────────────────────────────────────────
    // Step 3: Drop and recreate share_invites (slimmed; D-05)
    //
    // Target columns (from share-invite.entity.ts — 66-03):
    //   id, token, sharer_id, share_root_ipns_name, root_node_id, root_generation,
    //   item_name_encrypted, encrypted_read_key, encrypted_write_key,
    //   status, max_claims, claim_count, claimed_by, expires_at, created_at
    //
    // Dropped: encrypted_child_keys (jsonb column from pre-66 schema)
    // Unique: token
    // FK: sharer_id → users(id) ON DELETE CASCADE
    // ──────────────────────────────────────────────────────────────────────────
    await queryRunner.query(`DROP TABLE IF EXISTS "share_invites" CASCADE`);

    await queryRunner.query(`
      CREATE TABLE "share_invites" (
        "id"                   uuid NOT NULL DEFAULT uuid_generate_v4(),
        "token"                varchar(44) NOT NULL,
        "sharer_id"            uuid NOT NULL,
        "share_root_ipns_name" varchar(255) NOT NULL,
        "root_node_id"         uuid NOT NULL,
        "root_generation"      bigint NOT NULL DEFAULT 0,
        "item_name_encrypted"  bytea,
        "encrypted_read_key"   bytea NOT NULL,
        "encrypted_write_key"  bytea,
        "status"               varchar(20) NOT NULL DEFAULT 'active',
        "max_claims"           integer NOT NULL DEFAULT 1,
        "claim_count"          integer NOT NULL DEFAULT 0,
        "claimed_by"           uuid,
        "expires_at"           TIMESTAMP NOT NULL,
        "created_at"           TIMESTAMP NOT NULL DEFAULT now(),
        CONSTRAINT "PK_share_invites" PRIMARY KEY ("id"),
        CONSTRAINT "UQ_share_invites_token" UNIQUE ("token"),
        CONSTRAINT "CHK_share_invites_claim_count" CHECK ("claim_count" >= 0 AND "claim_count" <= "max_claims")
      )
    `);

    await queryRunner.query(`
      ALTER TABLE "share_invites"
      ADD CONSTRAINT "FK_share_invites_sharer" FOREIGN KEY ("sharer_id")
        REFERENCES "users" ("id") ON DELETE CASCADE ON UPDATE NO ACTION
    `);

    await queryRunner.query(
      `CREATE INDEX "IDX_share_invites_sharer_id" ON "share_invites" ("sharer_id")`
    );
    await queryRunner.query(
      `CREATE INDEX "IDX_share_invites_expires_at" ON "share_invites" ("expires_at")`
    );
    // Composite index for the (sharer_id, share_root_ipns_name) access path used by
    // getInvitesForItem (D-09) and ownership-scoped invite lookups.
    await queryRunner.query(
      `CREATE INDEX "IDX_share_invites_sharer_root" ON "share_invites" ("sharer_id", "share_root_ipns_name")`
    );

    // ──────────────────────────────────────────────────────────────────────────
    // Step 4: Drop folder_ipns
    //
    // FK-map confirmed: no table holds a SQL FK to folder_ipns(id).
    // ipns_republish_schedule, vaults, and shares reference ipns_name as plain
    // varchar(255) only — no cascade FK drops are needed here.
    // ──────────────────────────────────────────────────────────────────────────
    await queryRunner.query(`DROP TABLE IF EXISTS "folder_ipns" CASCADE`);

    // ──────────────────────────────────────────────────────────────────────────
    // Step 5: Create ipns_records
    //
    // Target columns (from ipns-record.entity.ts — 66-01):
    //   id, user_id, ipns_name, latest_cid, sequence_number, signed_record,
    //   encrypted_ipns_private_key, key_epoch, is_root,
    //   tombstoned_at (NEW), generation (NEW), created_at, updated_at
    //
    // Dropped vs folder_ipns: public_key (derivable via publicKeyFromIpnsName; D-02)
    // Unique: (ipns_name) — one canonical record per IPNS name
    // FK: user_id → users(id) ON DELETE CASCADE
    // ──────────────────────────────────────────────────────────────────────────
    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "ipns_records" (
        "id"                         uuid NOT NULL DEFAULT uuid_generate_v4(),
        "user_id"                    uuid NOT NULL,
        "ipns_name"                  varchar(255) NOT NULL,
        "latest_cid"                 varchar(255),
        "sequence_number"            bigint NOT NULL DEFAULT 0,
        "signed_record"              bytea,
        "encrypted_ipns_private_key" bytea,
        "key_epoch"                  integer,
        "is_root"                    boolean NOT NULL DEFAULT false,
        "tombstoned_at"              timestamptz,
        "generation"                 bigint NOT NULL DEFAULT 0,
        "created_at"                 TIMESTAMP NOT NULL DEFAULT now(),
        "updated_at"                 TIMESTAMP NOT NULL DEFAULT now(),
        CONSTRAINT "PK_ipns_records" PRIMARY KEY ("id"),
        CONSTRAINT "UQ_ipns_records_ipns_name" UNIQUE ("ipns_name"),
        CONSTRAINT "FK_ipns_records_user" FOREIGN KEY ("user_id")
          REFERENCES "users" ("id") ON DELETE CASCADE ON UPDATE NO ACTION
      )
    `);

    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "IDX_ipns_records_user_id" ON "ipns_records" ("user_id")`
    );
  }

  public async down(_queryRunner: QueryRunner): Promise<void> {
    throw new Error(
      'down() not implemented: greenfield drop-recreate migration (D-01). ' +
        'No rollback target — staging DB is wiped on each deploy.'
    );
  }
}
