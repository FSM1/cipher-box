import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Add UNIQUE constraint on (type, identifier_hash) in auth_methods.
 *
 * Prevents duplicate auth method creation from concurrent linkMethod requests.
 * Replaces the existing non-unique composite index.
 */
export class AddAuthMethodsUniqueConstraint1740200000000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP INDEX IF EXISTS "IDX_auth_methods_type_hash"`);
    await queryRunner.query(
      `CREATE UNIQUE INDEX "UQ_auth_methods_type_hash" ON "auth_methods" ("type", "identifier_hash")`
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP INDEX IF EXISTS "UQ_auth_methods_type_hash"`);
    await queryRunner.query(
      `CREATE INDEX "IDX_auth_methods_type_hash" ON "auth_methods" ("type", "identifier_hash")`
    );
  }
}
