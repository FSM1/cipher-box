"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AddTokenPrefix1738972800000 = void 0;
class AddTokenPrefix1738972800000 {
    async up(queryRunner) {
        // Idempotent: column may already exist if FullSchema baseline ran first
        await queryRunner.query(`ALTER TABLE "refresh_tokens" ADD COLUMN IF NOT EXISTS "tokenPrefix" varchar(16)`);
        await queryRunner.query(`CREATE INDEX IF NOT EXISTS "IDX_refresh_token_prefix" ON "refresh_tokens" ("tokenPrefix")`);
    }
    async down(queryRunner) {
        await queryRunner.query(`DROP INDEX IF EXISTS "IDX_refresh_token_prefix"`);
        await queryRunner.query(`ALTER TABLE "refresh_tokens" DROP COLUMN IF EXISTS "tokenPrefix"`);
    }
}
exports.AddTokenPrefix1738972800000 = AddTokenPrefix1738972800000;
//# sourceMappingURL=1738972800000-AddTokenPrefix.js.map