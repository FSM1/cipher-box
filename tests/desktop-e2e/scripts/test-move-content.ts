#!/usr/bin/env node
// test-move-content.ts -- Cross-platform desktop E2E: moving a file between
// folders must preserve its decrypted content.
//
// A file's FileMetadata is AES-256-GCM sealed with its PARENT folder's key, so a
// cross-folder move must re-encrypt the record under the destination folderKey
// (FUSE `handle_rename` on macOS/Linux, WinFsp `handle_rename` on Windows). This
// test performs the move THROUGH THE MOUNT -- the only OS-specific step, handled
// uniformly by `node:fs.renameSync` -- then reads the file back via a FRESH SDK
// client under the DESTINATION folderKey. That fresh decrypt is exactly what
// fails if the re-encryption is missing (the staging "Decryption failed" bug).
//
// One implementation for every platform: each run-all runner just invokes
// `tsx` on this file. Strict on all platforms; generous retries absorb IPNS
// propagation / FUSE-T SMB cache timing.
//
// Usage: tsx test-move-content.ts --mount <path> --api-url <url>
// Env:   TEST_SECRET (required) -- shared secret for /auth/test-login.

import { mkdirSync, writeFileSync, readdirSync, statSync, rmSync, renameSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, '../../..');
const VERIFY_SCRIPT = join(REPO_ROOT, 'packages/sdk-core/scripts/verify-filepointer.mts');
// tsx's real JS CLI entry (the `bin` target). We invoke this with `node` rather
// than node_modules/.bin/tsx because that .bin entry is a POSIX shell shim, and
// `node <shell-shim>` fails with a SyntaxError. Pointing node at the .mjs CLI is
// cross-platform (no shell shim, no PATH/pnpm dependency).
const TSX_CLI = join(REPO_ROOT, 'node_modules/tsx/dist/cli.mjs');

// The desktop launches with --dev-key, which maps to this fixed test identity;
// verify-filepointer.mts authenticates as the same user via /auth/test-login.
const TEST_EMAIL = 'dev-key@cipherbox.local';

function parseArgs(argv: string[]): Map<string, string> {
  const values = new Map<string, string>();
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith('--')) throw new Error(`Unexpected argument: ${token}`);
    const key = token.slice(2);
    const value = argv[i + 1];
    if (value === undefined || value.startsWith('--')) {
      throw new Error(`Missing value for --${key}`);
    }
    values.set(key, value);
    i += 1;
  }
  return values;
}

const args = parseArgs(process.argv.slice(2));
const mount =
  args.get('mount') || join(process.env.HOME || process.env.USERPROFILE || '', 'CipherBox');
const apiUrl = args.get('api-url') || 'http://localhost:3000';
const secret = process.env.TEST_SECRET;
if (!secret) {
  console.error('TEST_SECRET environment variable is required');
  process.exit(1);
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

// Nudge the mount so the FUSE/WinFsp layer re-resolves metadata (mirrors the
// `ls`/`stat` the shell harness used between polls). Best-effort.
function nudge(...paths: string[]): void {
  for (const p of paths) {
    try {
      statSync(p);
    } catch {
      /* not visible yet */
    }
    try {
      readdirSync(p);
    } catch {
      /* not a dir / not visible yet */
    }
  }
}

// Read a file back via a FRESH SDK client and assert its decrypted content.
// Returns true only when verify-filepointer.ts exits 0 (content matched under
// the resolved folderKey).
function verify({
  fileName,
  folderName,
  content,
}: {
  fileName: string;
  folderName?: string;
  content: string;
}): { ok: boolean; output: string } {
  const cliArgs = [
    VERIFY_SCRIPT,
    '--api-url',
    apiUrl,
    '--email',
    TEST_EMAIL,
    '--file-name',
    fileName,
    '--expected-content',
    content,
  ];
  if (folderName) {
    cliArgs.push('--folder-name', folderName);
  }
  // node can't run a .mts file directly, so run it through tsx's JS CLI entry.
  // process.execPath is the running node binary; TSX_CLI is tsx's .mjs CLI (not
  // the node_modules/.bin/tsx shell shim, which node cannot parse).
  const result = spawnSync(process.execPath, [TSX_CLI, ...cliArgs], {
    env: { ...process.env, TEST_SECRET: secret },
    encoding: 'utf8',
    // Bound the child: a stalled verify must not hang the whole suite — pollVerify
    // cannot recover from a blocking spawnSync. A timeout returns a non-zero status
    // so the poll loop treats it as a failed attempt and retries.
    timeout: 60_000,
    maxBuffer: 1024 * 1024,
  });
  if (result.error) {
    return { ok: false, output: `verify-filepointer failed to execute: ${result.error.message}` };
  }
  // The verifier never prints secrets (it refuses --secret; TEST_SECRET is env-only),
  // so its stdout/stderr are safe to surface for diagnostics on final failure.
  const output = [result.stdout, result.stderr].filter(Boolean).join('\n').trim();
  return { ok: result.status === 0, output };
}

async function pollVerify(
  label: string,
  opts: { fileName: string; folderName?: string; content: string },
  nudgePaths: string[]
): Promise<boolean> {
  const ATTEMPTS = 24;
  const DELAY_MS = 5000;
  let lastOutput = '';
  for (let attempt = 1; attempt <= ATTEMPTS; attempt += 1) {
    nudge(...nudgePaths);
    await sleep(DELAY_MS);
    const res = verify(opts);
    if (res.ok) {
      return true;
    }
    lastOutput = res.output;
  }
  console.error(`FAIL: ${label} did not verify after ${ATTEMPTS} attempts`);
  // Surface the last verifier output so the failure is self-diagnosing instead of
  // forcing a separate log-forensics pass (the child output was previously swallowed).
  if (lastOutput) {
    const indented = lastOutput
      .split('\n')
      .map((line) => `    ${line}`)
      .join('\n');
    console.error(`  last verifier output:\n${indented}`);
  }
  return false;
}

async function main(): Promise<void> {
  // Math.random/Date are fine here (this is a plain Node script, not a workflow).
  const tag = `${process.pid}-${Date.now()}`;
  const moveFile = `move-reencrypt-${tag}.txt`;
  const moveSubdir = `move-dest-${tag}`;
  const moveContent = 'content must survive re-encryption on move';

  console.log('=== Move-content E2E (cross-platform) ===');
  console.log(`Mount point: ${mount}`);
  console.log(`API URL:     ${apiUrl}`);
  console.log(`File:        ${moveFile} -> ${moveSubdir}/${moveFile}`);

  let failed = false;
  try {
    writeFileSync(join(mount, moveFile), moveContent);
    mkdirSync(join(mount, moveSubdir), { recursive: true });
    await sleep(2000);
    nudge(mount);

    // 1. Confirm initial encryption is good: file readable via the SDK at root.
    if (
      !(await pollVerify('pre-move root verify', { fileName: moveFile, content: moveContent }, [
        mount,
      ]))
    ) {
      console.error('FAIL: file not decryptable via SDK before move');
      failed = true;
    } else {
      // 2. Move THROUGH THE MOUNT (fs.renameSync == the OS rename the FUSE/WinFsp
      //    rename handler services; it must re-encrypt FileMetadata to the dest key).
      renameSync(join(mount, moveFile), join(mount, moveSubdir, moveFile));
      await sleep(3000);
      nudge(mount, join(mount, moveSubdir));

      // 3. Read back via a FRESH SDK client under the DESTINATION folderKey.
      if (
        await pollVerify(
          'post-move subfolder verify',
          { fileName: moveFile, folderName: moveSubdir, content: moveContent },
          [join(mount, moveSubdir)]
        )
      ) {
        console.log('PASS: moved file decrypts under destination folderKey (re-encryption OK)');
      } else {
        console.error(
          'FAIL: moved file not decryptable under destination key (re-encryption failed)'
        );
        failed = true;
      }
    }
  } finally {
    try {
      rmSync(join(mount, moveSubdir), { recursive: true, force: true });
    } catch {
      /* best-effort cleanup */
    }
    try {
      rmSync(join(mount, moveFile), { force: true });
    } catch {
      /* best-effort cleanup */
    }
  }

  process.exit(failed ? 1 : 0);
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
