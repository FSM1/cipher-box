import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddMailboxReceivedAtIndex1784692000000 implements MigrationInterface {
  name = 'AddMailboxReceivedAtIndex1784692000000';

  // CREATE/DROP INDEX CONCURRENTLY cannot run inside a transaction, so TypeORM
  // must not wrap this migration in one — it builds the sweep-scan index without
  // taking a table lock that would block concurrent post/poll/ack writes.
  public transaction = false as const;

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `CREATE INDEX CONCURRENTLY "idx_mailbox_received_at" ON "mailbox_messages" ("received_at") `
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP INDEX CONCURRENTLY "public"."idx_mailbox_received_at"`);
  }
}
