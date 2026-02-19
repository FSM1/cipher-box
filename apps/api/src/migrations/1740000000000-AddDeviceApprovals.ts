import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Add device_approvals table for MFA device approval flow.
 *
 * This table was previously only created via synchronize:true in dev/test
 * and was missing from production/staging migrations.
 */
export class AddDeviceApprovals1740000000000 implements MigrationInterface {
  name = 'AddDeviceApprovals1740000000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "device_approvals" (
        "id"                    uuid DEFAULT uuid_generate_v4() NOT NULL,
        "user_id"               varchar NOT NULL,
        "device_id"             varchar NOT NULL,
        "device_name"           varchar NOT NULL,
        "ephemeral_public_key"  text NOT NULL,
        "status"                varchar NOT NULL DEFAULT 'pending',
        "encrypted_factor_key"  text,
        "created_at"            TIMESTAMP NOT NULL DEFAULT now(),
        "expires_at"            TIMESTAMP NOT NULL,
        "responded_by"          varchar,
        CONSTRAINT "PK_device_approvals" PRIMARY KEY ("id")
      )
    `);

    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "idx_device_approvals_user_status" ON "device_approvals" ("user_id", "status")`
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP INDEX IF EXISTS "idx_device_approvals_user_status"`);
    await queryRunner.query(`DROP TABLE IF EXISTS "device_approvals"`);
  }
}
