import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddByoUserFlag1740600000000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE vaults ADD COLUMN IF NOT EXISTS is_byo_user BOOLEAN NOT NULL DEFAULT false
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TABLE vaults DROP COLUMN IF EXISTS is_byo_user`);
  }
}
