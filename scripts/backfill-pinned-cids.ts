/**
 * One-shot backfill script: repairs quota inflation accumulated while
 * recordUnpin had zero callers.
 *
 * For each NON-BYO user, diffs their pinned_cids rows against the live
 * Kubo pin set and deletes rows whose CID is no longer physically pinned
 * (phantom rows that inflated SUM(size_bytes)).
 *
 * BYO users are EXCLUDED entirely (D-09). Their advisory rows reference
 * CIDs that were never on CipherBox's Kubo node, so a "not on Kubo"
 * signal is meaningless and deleting their rows would corrupt advisory quota.
 *
 * Usage:
 *   ts-node scripts/backfill-pinned-cids.ts [--dry-run]
 *
 * Flags:
 *   --dry-run  Report candidates without deleting (safe preview mode).
 *              Default mode performs the actual DELETE.
 *
 * Safety guards:
 *   - An empty or unreachable Kubo pin set aborts with exit(1) and NO deletes.
 *   - --dry-run banner is printed at start so accidental runs are visible.
 *   - Deletes are id-scoped (WHERE id = ANY), never a blanket DELETE FROM.
 *   - Reuses run-migrations.ts DataSource bootstrap + secret-redacting error handler.
 */
import { DataSource } from 'typeorm';
import { config } from 'dotenv';
import {
  parseKuboPinLs,
  selectRowsToDelete,
  type BackfillRow,
} from '../apps/api/src/scripts/backfill-helpers';

config();

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const BATCH_SIZE = 10;
const DRY_RUN = process.argv.includes('--dry-run');
const KUBO_API_URL = process.env.IPFS_LOCAL_API_URL ?? 'http://localhost:5001';
// Bound the Kubo pin/ls fetch so a network stall can't hang the backfill
// (matches pending-unpin.processor.ts). A timeout aborts into the catch below,
// which exits non-zero with zero deletes.
const KUBO_PIN_LS_TIMEOUT_MS = 30_000;

// ---------------------------------------------------------------------------
// DataSource — mirrors run-migrations.ts bootstrap exactly
// ---------------------------------------------------------------------------

const dataSource = new DataSource({
  type: 'postgres',
  host: process.env.DB_HOST ?? 'localhost',
  port: parseInt(process.env.DB_PORT ?? '5432', 10),
  username: process.env.DB_USERNAME ?? 'postgres',
  password: process.env.DB_PASSWORD ?? 'postgres',
  database: process.env.DB_DATABASE ?? 'cipherbox',
  entities: ['dist/**/*.entity.js'],
  migrations: ['dist/migrations/*.js'],
  logging: ['error'],
});

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function run(): Promise<void> {
  // Print mode banner so an operator can spot accidental destructive runs.
  if (DRY_RUN) {
    console.log('=======================================================');
    console.log('  MODE: DRY-RUN — no rows will be deleted');
    console.log('=======================================================');
  } else {
    console.log('=======================================================');
    console.log('  MODE: DELETE — phantom rows will be permanently deleted');
    console.log('=======================================================');
  }

  try {
    await dataSource.initialize();
    console.log('Database connected.');

    // -------------------------------------------------------------------
    // 1. Fetch the live Kubo pin set (MANDATORY GUARD: empty/unreachable aborts)
    // -------------------------------------------------------------------
    let kuboPinSet: Set<string>;
    try {
      const res = await fetch(`${KUBO_API_URL}/api/v0/pin/ls?type=recursive`, {
        method: 'POST',
        signal: AbortSignal.timeout(KUBO_PIN_LS_TIMEOUT_MS),
      });
      if (!res.ok) {
        const errText = await res.text().catch(() => '(unreadable)');
        console.error(
          `ERROR: Kubo pin/ls returned HTTP ${res.status}: ${errText}. Aborting without deleting.`
        );
        await dataSource.destroy();
        process.exit(1);
      }
      const text = await res.text();
      kuboPinSet = parseKuboPinLs(text);
    } catch (fetchErr: unknown) {
      // Kubo unreachable — abort, never interpret as "all rows are phantoms"
      const msg = fetchErr instanceof Error ? fetchErr.message : String(fetchErr);
      console.error(
        `ERROR: Kubo pin/ls fetch failed (unreachable?): ${msg}. Aborting without deleting.`
      );
      await dataSource.destroy();
      process.exit(1);
    }

    // Safety guard: an empty set means we could not enumerate real pins.
    // Treating it as "all CIDs absent" would wipe every non-BYO row.
    if (kuboPinSet.size === 0) {
      console.error(
        'ERROR: Kubo pin set is empty. Either Kubo has no pins or the parse failed. ' +
          'Aborting without deleting to avoid wiping all non-BYO rows.'
      );
      await dataSource.destroy();
      process.exit(1);
    }
    console.log(`Kubo pin set fetched: ${kuboPinSet.size} CIDs.`);

    // -------------------------------------------------------------------
    // 2. Query candidate rows — non-BYO users only (D-09)
    //
    // JOIN pinned_cids to vaults on user_id = owner_id and filter
    // vaults.is_byo_user = false. BYO rows are excluded at query level;
    // selectRowsToDelete re-asserts isByoUser === false defensively.
    //
    // WR-05: add age cutoff (pinned_at < NOW() - INTERVAL '1 hour') so in-flight
    // uploads inside the active-upload race window are never selected as phantom rows.
    // Without this a row written less than a second ago (upload just completed, but
    // Kubo pin list not yet refreshed) would be deleted as a phantom.
    //
    // WR-06: project the real v.is_byo_user instead of the hardcoded false::boolean
    // so the defensive !row.isByoUser re-assert in selectRowsToDelete is meaningful.
    // The WHERE v.is_byo_user = false query-level guard is kept; the projection fix
    // ensures the in-code re-assert sees the actual vault value, not a constant.
    // -------------------------------------------------------------------
    const candidateRows = (await dataSource.query(`
      SELECT
        pc.id              AS "id",
        pc.user_id         AS "userId",
        pc.cid             AS "cid",
        v.is_byo_user      AS "isByoUser"
      FROM pinned_cids pc
      JOIN vaults v ON v.owner_id = pc.user_id
      WHERE v.is_byo_user = false
        AND pc.pinned_at < NOW() - INTERVAL '1 hour'
    `)) as BackfillRow[];

    console.log(`Candidate rows (non-BYO pinned_cids): ${candidateRows.length}`);

    // -------------------------------------------------------------------
    // 3. Apply D-09 predicate: non-BYO rows whose CID is absent from Kubo
    // -------------------------------------------------------------------
    const rowsToDelete = selectRowsToDelete(candidateRows, kuboPinSet);
    console.log(`Phantom rows (absent from Kubo): ${rowsToDelete.length}`);

    if (rowsToDelete.length === 0) {
      console.log('Nothing to delete. Quota is already accurate. Exiting cleanly.');
      await dataSource.destroy();
      process.exit(0);
    }

    if (DRY_RUN) {
      // -------------------------------------------------------------------
      // Dry-run: report without deleting
      // -------------------------------------------------------------------
      console.log('\n--- DRY-RUN: rows that WOULD be deleted (sample up to 20) ---');
      const sample = rowsToDelete.slice(0, 20);
      for (const row of sample) {
        console.log(`  userId=${row.userId}  cid=${row.cid}  id=${row.id}`);
      }
      if (rowsToDelete.length > 20) {
        console.log(`  ... and ${rowsToDelete.length - 20} more`);
      }
      console.log('\nDRY-RUN complete. No rows were deleted.');
    } else {
      // -------------------------------------------------------------------
      // Live delete in batches (BATCH_SIZE = 10, mirrors migration.processor)
      // -------------------------------------------------------------------
      let totalDeleted = 0;
      let failedBatches = 0;
      const ids = rowsToDelete.map((r) => r.id);

      for (let i = 0; i < ids.length; i += BATCH_SIZE) {
        const batch = ids.slice(i, i + BATCH_SIZE);
        try {
          await dataSource.query(`DELETE FROM pinned_cids WHERE id = ANY($1)`, [batch]);
          totalDeleted += batch.length;
          console.log(`  Deleted batch offset=${i} size=${batch.length} (total=${totalDeleted})`);
        } catch (batchErr: unknown) {
          failedBatches += 1;
          const msg = batchErr instanceof Error ? batchErr.message : String(batchErr);
          console.error(
            `  ERROR at batch offset=${i}: ${msg}. Skipping batch; remaining batches continue.`
          );
        }
      }

      console.log(
        `\nBackfill complete. Total rows deleted: ${totalDeleted} / ${rowsToDelete.length}`
      );

      // A partial backfill must not look healthy to automation — exit non-zero.
      if (failedBatches > 0) {
        console.error(
          `Backfill finished with ${failedBatches} failed batch(es); exiting non-zero.`
        );
        await dataSource.destroy();
        process.exit(1);
      }
    }

    await dataSource.destroy();
    process.exit(0);
  } catch (error: unknown) {
    const err = error instanceof Error ? error : new Error(String(error));
    console.error(
      'Backfill failed:',
      err.name ?? 'UnknownError',
      // Redact DB credentials from connection error messages (mirrors run-migrations.ts)
      (err.message ?? '').replace(/((?:host|password|user(?:name)?)=)[^\s;,]+/gi, '$1***')
    );
    process.exit(1);
  }
}

run();
