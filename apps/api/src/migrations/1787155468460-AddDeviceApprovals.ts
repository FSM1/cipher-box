import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddDeviceApprovals1787155468460 implements MigrationInterface {
  name = 'AddDeviceApprovals1787155468460';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `CREATE TABLE "device_approvals" ("id" uuid NOT NULL DEFAULT gen_random_uuid(), "user_id" uuid NOT NULL, "requester_device_public_key" character varying(64) NOT NULL, "ephemeral_public_key" character varying(66) NOT NULL, "request_signature" character varying(128) NOT NULL, "status" character varying(16) NOT NULL, "sealed_factor" bytea, "responder_device_public_key" character varying(64), "response_signature" character varying(128), "created_at" TIMESTAMP WITH TIME ZONE NOT NULL, "expires_at" TIMESTAMP WITH TIME ZONE NOT NULL, CONSTRAINT "PK_0d0bb20e374a7a98268f16a3cd2" PRIMARY KEY ("id"))`
    );
    await queryRunner.query(
      `CREATE INDEX "idx_device_approvals_expires_at" ON "device_approvals" ("expires_at") `
    );
    await queryRunner.query(
      `CREATE INDEX "idx_device_approvals_user_expires" ON "device_approvals" ("user_id", "expires_at") `
    );
    await queryRunner.query(
      `CREATE TABLE "account_devices" ("id" uuid NOT NULL DEFAULT gen_random_uuid(), "user_id" uuid NOT NULL, "identity_subject_id" uuid NOT NULL, "public_key" character varying(64) NOT NULL, "label" character varying(64), "created_at" TIMESTAMP WITH TIME ZONE NOT NULL, "last_seen_at" TIMESTAMP WITH TIME ZONE NOT NULL, CONSTRAINT "uq_account_devices_public_key" UNIQUE ("public_key"), CONSTRAINT "PK_19286b4d50cac9db850e3895cf4" PRIMARY KEY ("id"))`
    );
    await queryRunner.query(
      `CREATE INDEX "idx_account_devices_identity_subject" ON "account_devices" ("identity_subject_id") `
    );
    await queryRunner.query(
      `CREATE INDEX "idx_account_devices_user_id" ON "account_devices" ("user_id") `
    );
    await queryRunner.query(
      `ALTER TABLE "device_approvals" ADD CONSTRAINT "FK_8deb3bdfc105ac099796563f6cc" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE NO ACTION`
    );
    await queryRunner.query(
      `ALTER TABLE "account_devices" ADD CONSTRAINT "FK_7db6ef5ecebaf3f47b7db0486a6" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE NO ACTION`
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "account_devices" DROP CONSTRAINT "FK_7db6ef5ecebaf3f47b7db0486a6"`
    );
    await queryRunner.query(
      `ALTER TABLE "device_approvals" DROP CONSTRAINT "FK_8deb3bdfc105ac099796563f6cc"`
    );
    await queryRunner.query(`DROP INDEX "public"."idx_account_devices_user_id"`);
    await queryRunner.query(`DROP INDEX "public"."idx_account_devices_identity_subject"`);
    await queryRunner.query(`DROP TABLE "account_devices"`);
    await queryRunner.query(`DROP INDEX "public"."idx_device_approvals_user_expires"`);
    await queryRunner.query(`DROP INDEX "public"."idx_device_approvals_expires_at"`);
    await queryRunner.query(`DROP TABLE "device_approvals"`);
  }
}
