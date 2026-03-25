import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddPinMigrations1742000000000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS pin_migrations (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL,
        status VARCHAR(20) NOT NULL DEFAULT 'pending',
        total_cids INT NOT NULL DEFAULT 0,
        migrated_cids INT NOT NULL DEFAULT 0,
        failed_cids INT NOT NULL DEFAULT 0,
        source_config_encrypted TEXT NOT NULL,
        dest_config_encrypted TEXT NOT NULL,
        failed_cid_list TEXT,
        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
        completed_at TIMESTAMP
      )
    `);
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS idx_pin_migrations_user_id ON pin_migrations(user_id)`
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE IF EXISTS pin_migrations`);
  }
}
