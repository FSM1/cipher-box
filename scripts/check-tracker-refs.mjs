// Fails when source names a tracking issue. A comment saying `#1234` asserts
// something about the tracker, which moves independently of the code — nothing
// in CI, review, or the type system catches the claim going stale. State the
// condition instead ("no production implementation yet; tests fake this"): it is
// checkable from the code and stops being true in the diff that falsifies it.
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const ROOTS = ['crates', 'apps', 'packages', 'landing', 'tools'];
const EXTENSIONS = /\.(rs|ts|tsx|js|jsx|mjs|cjs)$/;

// Generated or vendored trees whose comments are not ours to write.
const SKIP = [/^apps\/web\/src\/wasm\//, /\/test\/browser\/pkg\//, /\/vendor\//];

// `(?<![&\w:])` drops HTML entities (`&#9660;`), format specs (`{:#010o}`) and
// repo-qualified references (`FSM1/cipher-box-next#32`, which names a durable
// decision record, not a ticket); the trailing lookahead drops CSS hex colours,
// whose next char is a hex digit (`#006644`).
const TRACKER_REF = /(?<![&\w:])#\d{3,4}(?![\da-fA-F])/g;

// Genuine exceptions, each with the reason it is not a tracker reference.
// Entries are matched as `path` plus a substring of the offending line.
const ALLOWLIST = [];

const isAllowed = (path, line) =>
  ALLOWLIST.some((entry) => entry.path === path && line.includes(entry.match));

const tracked = execFileSync('git', ['ls-files', '-z', ...ROOTS], { encoding: 'utf8' })
  .split('\0')
  .filter((path) => path && EXTENSIONS.test(path) && !SKIP.some((re) => re.test(path)));

const offences = [];
for (const path of tracked) {
  const lines = readFileSync(path, 'utf8').split('\n');
  lines.forEach((line, index) => {
    for (const [token] of line.matchAll(TRACKER_REF)) {
      if (!isAllowed(path, line)) {
        offences.push({ path, line: index + 1, token, text: line.trim() });
      }
    }
  });
}

if (offences.length > 0) {
  console.error(`Found ${offences.length} tracking-issue reference(s) in source:\n`);
  for (const { path, line, token, text } of offences) {
    console.error(`  ${path}:${line}  ${token}\n    ${text}`);
  }
  console.error(
    '\nReplace each with the condition it stands for — a statement checkable from' +
      '\nthe code, which stops being true when someone changes the code. If a match' +
      '\nis not a tracker reference, add it to ALLOWLIST in this script with a reason.'
  );
  process.exit(1);
}

console.log(`No tracking-issue references in ${tracked.length} source files.`);
