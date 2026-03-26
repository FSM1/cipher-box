import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddWritableShares1743000000000 implements MigrationInterface {
  name = 'AddWritableShares1743000000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "shares" ADD COLUMN IF NOT EXISTS "permission" varchar(10) NOT NULL DEFAULT 'read'`
    );
    await queryRunner.query(
      `ALTER TABLE "shares" ADD COLUMN IF NOT EXISTS "encrypted_ipns_key" bytea`
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TABLE "shares" DROP COLUMN IF EXISTS "encrypted_ipns_key"`);
    await queryRunner.query(`ALTER TABLE "shares" DROP COLUMN IF EXISTS "permission"`);
  }
}
