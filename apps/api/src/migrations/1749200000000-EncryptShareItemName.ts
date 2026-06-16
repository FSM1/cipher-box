import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * REQ-4 / Phase-14 finding M1: encrypt share/invite display names at rest.
 *
 * Additive + nullable only. The server is zero-knowledge and has no recipient
 * (or ephemeral) private key, so it CANNOT encrypt existing plaintext rows --
 * there is deliberately NO data UPDATE here. Legacy rows keep plaintext in
 * `item_name` until a key-holding client lazily backfills `item_name_encrypted`
 * (decision A2, plan 48-06). New shares and invites persist ciphertext only.
 *
 * Idempotent (IF NOT EXISTS / IF EXISTS) per DATABASE_EVOLUTION_PROTOCOL.
 */
export class EncryptShareItemName1749200000000 implements MigrationInterface {
  name = 'EncryptShareItemName1749200000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "shares" ADD COLUMN IF NOT EXISTS "item_name_encrypted" bytea`
    );
    await queryRunner.query(
      `ALTER TABLE "share_invites" ADD COLUMN IF NOT EXISTS "item_name_encrypted" bytea`
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "share_invites" DROP COLUMN IF EXISTS "item_name_encrypted"`
    );
    await queryRunner.query(`ALTER TABLE "shares" DROP COLUMN IF EXISTS "item_name_encrypted"`);
  }
}
