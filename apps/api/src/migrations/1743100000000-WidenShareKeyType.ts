import { MigrationInterface, QueryRunner } from 'typeorm';

export class WidenShareKeyType1743100000000 implements MigrationInterface {
  name = 'WidenShareKeyType1743100000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // Widen key_type from varchar(10) to varchar(12) to accommodate 'folder-ipns' (11 chars)
    await queryRunner.query(`ALTER TABLE "share_keys" ALTER COLUMN "key_type" TYPE varchar(12)`);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TABLE "share_keys" ALTER COLUMN "key_type" TYPE varchar(10)`);
  }
}
