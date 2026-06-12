import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddPendingUnpins1749000000000 implements MigrationInterface {
  name = 'AddPendingUnpins1749000000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS pending_unpins (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        cid VARCHAR(255) NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT NOW()
      )
    `);
    await queryRunner.query(
      `CREATE UNIQUE INDEX IF NOT EXISTS idx_pending_unpins_cid ON pending_unpins(cid)`
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE IF EXISTS pending_unpins`);
  }
}
