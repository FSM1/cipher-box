import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddMailboxReceivedAtIndex1784692000000 implements MigrationInterface {
  name = 'AddMailboxReceivedAtIndex1784692000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `CREATE INDEX "idx_mailbox_received_at" ON "mailbox_messages" ("received_at") `
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP INDEX "public"."idx_mailbox_received_at"`);
  }
}
