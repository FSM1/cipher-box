import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Full schema baseline migration for CipherBox.
 *
 * Creates ALL tables from scratch for fresh database initialization (staging/production).
 * This migration captures the complete schema state as of Phase 9.1.
 *
 * Timestamp 1700000000000 ensures this runs BEFORE any incremental migrations.
 * For fresh databases: this creates everything; incremental migrations are idempotent (IF NOT EXISTS).
 * For existing databases created via synchronize:true: this migration will NOT be skipped
 *   automatically — you must manually insert a row into the `migrations` table to mark it
 *   as applied, or only run migrations against fresh databases.
 *
 * Tables created (9):
 *   users, refresh_tokens, auth_methods, vaults, pinned_cids,
 *   folder_ipns, tee_key_state, tee_key_rotation_log, ipns_republish_schedule
 */
export class FullSchema1700000000000 implements MigrationInterface {
  name = 'FullSchema1700000000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // Enable uuid-ossp extension for uuid_generate_v4()
    await queryRunner.query(`CREATE EXTENSION IF NOT EXISTS "uuid-ossp"`);

    // ──────────────────────────────────────────────
    // 1. users
    // ──────────────────────────────────────────────
    await queryRunner.query(`
      CREATE TABLE "users" (
        "id"                uuid NOT NULL DEFAULT uuid_generate_v4(),
        "publicKey"         varchar NOT NULL,
        "createdAt"         TIMESTAMP NOT NULL DEFAULT now(),
        "updatedAt"         TIMESTAMP NOT NULL DEFAULT now(),
        CONSTRAINT "PK_users" PRIMARY KEY ("id"),
        CONSTRAINT "UQ_users_publicKey" UNIQUE ("publicKey")
      )
    `);

    // ──────────────────────────────────────────────
    // 2. refresh_tokens
    // ──────────────────────────────────────────────
    await queryRunner.query(`
      CREATE TABLE "refresh_tokens" (
        "id"          uuid NOT NULL DEFAULT uuid_generate_v4(),
        "userId"      uuid NOT NULL,
        "tokenHash"   varchar NOT NULL,
        "tokenPrefix" varchar(16),
        "expiresAt"   TIMESTAMP NOT NULL,
        "revokedAt"   TIMESTAMP,
        "createdAt"   TIMESTAMP NOT NULL DEFAULT now(),
        CONSTRAINT "PK_refresh_tokens" PRIMARY KEY ("id"),
        CONSTRAINT "FK_refresh_tokens_user" FOREIGN KEY ("userId")
          REFERENCES "users" ("id") ON DELETE CASCADE ON UPDATE NO ACTION
      )
    `);

    // Index for token prefix lookups (added by incremental migration 1738972800000)
    await queryRunner.query(
      `CREATE INDEX "IDX_refresh_token_prefix" ON "refresh_tokens" ("tokenPrefix")`
    );

    // ──────────────────────────────────────────────
    // 3. auth_methods
    // ──────────────────────────────────────────────
    await queryRunner.query(`
      CREATE TABLE "auth_methods" (
        "id"                  uuid NOT NULL DEFAULT uuid_generate_v4(),
        "userId"              uuid NOT NULL,
        "type"                varchar NOT NULL,
        "identifier"          varchar NOT NULL,
        "identifier_hash"     varchar(64),
        "identifier_display"  varchar(255),
        "lastUsedAt"          TIMESTAMP,
        "createdAt"           TIMESTAMP NOT NULL DEFAULT now(),
        CONSTRAINT "PK_auth_methods" PRIMARY KEY ("id"),
        CONSTRAINT "FK_auth_methods_user" FOREIGN KEY ("userId")
          REFERENCES "users" ("id") ON DELETE CASCADE ON UPDATE NO ACTION
      )
    `);

    // Index on identifier_hash for wallet address lookup
    await queryRunner.query(
      `CREATE INDEX "IDX_auth_methods_identifier_hash" ON "auth_methods" ("identifier_hash")`
    );

    // Composite index on (type, identifier_hash) for efficient auth method lookups
    await queryRunner.query(
      `CREATE INDEX "IDX_auth_methods_type_hash" ON "auth_methods" ("type", "identifier_hash")`
    );

    // ──────────────────────────────────────────────
    // 4. vaults
    // ──────────────────────────────────────────────
    await queryRunner.query(`
      CREATE TABLE "vaults" (
        "id"                           uuid NOT NULL DEFAULT uuid_generate_v4(),
        "owner_id"                     uuid NOT NULL,
        "owner_public_key"             bytea NOT NULL,
        "encrypted_root_folder_key"    bytea NOT NULL,
        "encrypted_root_ipns_private_key" bytea NOT NULL,
        "root_ipns_public_key"         bytea NOT NULL,
        "root_ipns_name"               varchar(255) NOT NULL,
        "created_at"                   TIMESTAMP NOT NULL DEFAULT now(),
        "initialized_at"               TIMESTAMP,
        "updated_at"                   TIMESTAMP NOT NULL DEFAULT now(),
        CONSTRAINT "PK_vaults" PRIMARY KEY ("id")
      )
    `);

    // Unique index on owner_id (one vault per user)
    await queryRunner.query(`CREATE UNIQUE INDEX "IDX_vaults_owner_id" ON "vaults" ("owner_id")`);

    // Foreign key
    await queryRunner.query(`
      ALTER TABLE "vaults"
      ADD CONSTRAINT "FK_vaults_owner" FOREIGN KEY ("owner_id")
        REFERENCES "users" ("id") ON DELETE CASCADE ON UPDATE NO ACTION
    `);

    // ──────────────────────────────────────────────
    // 5. pinned_cids
    // ──────────────────────────────────────────────
    await queryRunner.query(`
      CREATE TABLE "pinned_cids" (
        "id"         uuid NOT NULL DEFAULT uuid_generate_v4(),
        "user_id"    uuid NOT NULL,
        "cid"        varchar(255) NOT NULL,
        "size_bytes" bigint NOT NULL,
        "pinned_at"  TIMESTAMP NOT NULL DEFAULT now(),
        CONSTRAINT "PK_pinned_cids" PRIMARY KEY ("id"),
        CONSTRAINT "UQ_pinned_cids_user_cid" UNIQUE ("user_id", "cid"),
        CONSTRAINT "FK_pinned_cids_user" FOREIGN KEY ("user_id")
          REFERENCES "users" ("id") ON DELETE CASCADE ON UPDATE NO ACTION
      )
    `);

    // Index on user_id for quota queries
    await queryRunner.query(`CREATE INDEX "IDX_pinned_cids_user_id" ON "pinned_cids" ("user_id")`);

    // ──────────────────────────────────────────────
    // 6. folder_ipns
    // ──────────────────────────────────────────────
    await queryRunner.query(`
      CREATE TABLE "folder_ipns" (
        "id"                         uuid NOT NULL DEFAULT uuid_generate_v4(),
        "user_id"                    uuid NOT NULL,
        "ipns_name"                  varchar(255) NOT NULL,
        "latest_cid"                 varchar(255),
        "sequence_number"            bigint NOT NULL DEFAULT 0,
        "encrypted_ipns_private_key" bytea,
        "key_epoch"                  integer,
        "is_root"                    boolean NOT NULL DEFAULT false,
        "created_at"                 TIMESTAMP NOT NULL DEFAULT now(),
        "updated_at"                 TIMESTAMP NOT NULL DEFAULT now(),
        CONSTRAINT "PK_folder_ipns" PRIMARY KEY ("id"),
        CONSTRAINT "UQ_folder_ipns_user_ipns" UNIQUE ("user_id", "ipns_name"),
        CONSTRAINT "FK_folder_ipns_user" FOREIGN KEY ("user_id")
          REFERENCES "users" ("id") ON DELETE CASCADE ON UPDATE NO ACTION
      )
    `);

    // Index on user_id for lookups
    await queryRunner.query(`CREATE INDEX "IDX_folder_ipns_user_id" ON "folder_ipns" ("user_id")`);

    // ──────────────────────────────────────────────
    // 7. tee_key_state (singleton row)
    // ──────────────────────────────────────────────
    await queryRunner.query(`
      CREATE TABLE "tee_key_state" (
        "id"                   uuid NOT NULL DEFAULT uuid_generate_v4(),
        "current_epoch"        integer NOT NULL,
        "current_public_key"   bytea NOT NULL,
        "previous_epoch"       integer,
        "previous_public_key"  bytea,
        "grace_period_ends_at" TIMESTAMP,
        "created_at"           TIMESTAMP NOT NULL DEFAULT now(),
        "updated_at"           TIMESTAMP NOT NULL DEFAULT now(),
        CONSTRAINT "PK_tee_key_state" PRIMARY KEY ("id")
      )
    `);

    // ──────────────────────────────────────────────
    // 8. tee_key_rotation_log
    // ──────────────────────────────────────────────
    await queryRunner.query(`
      CREATE TABLE "tee_key_rotation_log" (
        "id"              uuid NOT NULL DEFAULT uuid_generate_v4(),
        "from_epoch"      integer NOT NULL,
        "to_epoch"        integer NOT NULL,
        "from_public_key" bytea NOT NULL,
        "to_public_key"   bytea NOT NULL,
        "reason"          varchar(255) NOT NULL,
        "created_at"      TIMESTAMP NOT NULL DEFAULT now(),
        CONSTRAINT "PK_tee_key_rotation_log" PRIMARY KEY ("id")
      )
    `);

    // ──────────────────────────────────────────────
    // 9. ipns_republish_schedule
    // ──────────────────────────────────────────────
    await queryRunner.query(`
      CREATE TABLE "ipns_republish_schedule" (
        "id"                    uuid NOT NULL DEFAULT uuid_generate_v4(),
        "user_id"               uuid NOT NULL,
        "ipns_name"             varchar(255) NOT NULL,
        "encrypted_ipns_key"    bytea NOT NULL,
        "key_epoch"             integer NOT NULL,
        "latest_cid"            varchar(255) NOT NULL,
        "sequence_number"       bigint NOT NULL DEFAULT 0,
        "next_republish_at"     TIMESTAMP NOT NULL,
        "last_republish_at"     TIMESTAMP,
        "consecutive_failures"  integer NOT NULL DEFAULT 0,
        "status"                varchar(20) NOT NULL DEFAULT 'active',
        "last_error"            text,
        "created_at"            TIMESTAMP NOT NULL DEFAULT now(),
        "updated_at"            TIMESTAMP NOT NULL DEFAULT now(),
        CONSTRAINT "PK_ipns_republish_schedule" PRIMARY KEY ("id"),
        CONSTRAINT "UQ_ipns_republish_user_ipns" UNIQUE ("user_id", "ipns_name"),
        CONSTRAINT "FK_ipns_republish_user" FOREIGN KEY ("user_id")
          REFERENCES "users" ("id") ON DELETE CASCADE ON UPDATE NO ACTION
      )
    `);

    // Index on user_id for lookups
    await queryRunner.query(
      `CREATE INDEX "IDX_ipns_republish_user_id" ON "ipns_republish_schedule" ("user_id")`
    );

    // Composite index on status + next_republish_at for the republish cron query
    await queryRunner.query(
      `CREATE INDEX "IDX_ipns_republish_status_next" ON "ipns_republish_schedule" ("status", "next_republish_at")`
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Drop tables in reverse dependency order (children before parents)
    await queryRunner.query(`DROP TABLE IF EXISTS "ipns_republish_schedule" CASCADE`);
    await queryRunner.query(`DROP TABLE IF EXISTS "tee_key_rotation_log" CASCADE`);
    await queryRunner.query(`DROP TABLE IF EXISTS "tee_key_state" CASCADE`);
    await queryRunner.query(`DROP TABLE IF EXISTS "folder_ipns" CASCADE`);
    await queryRunner.query(`DROP TABLE IF EXISTS "pinned_cids" CASCADE`);
    await queryRunner.query(`DROP TABLE IF EXISTS "vaults" CASCADE`);
    await queryRunner.query(`DROP TABLE IF EXISTS "auth_methods" CASCADE`);
    await queryRunner.query(`DROP TABLE IF EXISTS "refresh_tokens" CASCADE`);
    await queryRunner.query(`DROP TABLE IF EXISTS "users" CASCADE`);
  }
}
