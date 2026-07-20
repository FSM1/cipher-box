import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddMailboxMessages1784519962991 implements MigrationInterface {
  name = 'AddMailboxMessages1784519962991';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `CREATE TABLE "mailbox_messages" ("id" uuid NOT NULL DEFAULT gen_random_uuid(), "recipient_public_key" character varying(130) NOT NULL, "idempotency_scope" character varying(64) NOT NULL, "blob" bytea NOT NULL, "received_at" TIMESTAMP WITH TIME ZONE NOT NULL, CONSTRAINT "PK_865e565d761179ce3e394b8b619" PRIMARY KEY ("id"))`
    );
    await queryRunner.query(
      `CREATE INDEX "idx_mailbox_recipient_received" ON "mailbox_messages" ("recipient_public_key", "received_at") `
    );
    await queryRunner.query(
      `CREATE UNIQUE INDEX "uq_mailbox_recipient_idempotency" ON "mailbox_messages" ("recipient_public_key", "idempotency_scope") `
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP INDEX "public"."uq_mailbox_recipient_idempotency"`);
    await queryRunner.query(`DROP INDEX "public"."idx_mailbox_recipient_received"`);
    await queryRunner.query(`DROP TABLE "mailbox_messages"`);
  }
}
