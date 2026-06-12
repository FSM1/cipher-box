import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddPinnedCidCidIndex1749100000000 implements MigrationInterface {
  name = 'AddPinnedCidCidIndex1749100000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`CREATE INDEX IF NOT EXISTS idx_pinned_cids_cid ON pinned_cids(cid)`);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP INDEX IF EXISTS idx_pinned_cids_cid`);
  }
}
