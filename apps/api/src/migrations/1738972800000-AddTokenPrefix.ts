import { MigrationInterface, QueryRunner, TableColumn } from 'typeorm';

export class AddTokenPrefix1738972800000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.addColumn(
      'refresh_tokens',
      new TableColumn({
        name: 'tokenPrefix',
        type: 'varchar',
        length: '16',
        isNullable: true,
      })
    );
    await queryRunner.query(
      `CREATE INDEX "IDX_refresh_token_prefix" ON "refresh_tokens" ("tokenPrefix")`
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropIndex('refresh_tokens', 'IDX_refresh_token_prefix');
    await queryRunner.dropColumn('refresh_tokens', 'tokenPrefix');
  }
}
