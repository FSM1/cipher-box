// Fails when source names a tracking issue — see the comment rules in AGENTS.md
// for why. Repo-qualified citations of the decision corpus are exempt; bare
// numbers and this repo's own issue URLs are not.
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const ROOTS = ['crates', 'apps', 'packages', 'landing', 'tools', 'scripts', '.github'];
const EXTENSIONS = /\.(rs|ts|tsx|mts|cts|js|jsx|mjs|cjs|toml|json|ya?ml|sh)$/;

// Generated or vendored trees whose comments are not ours to write.
const SKIP = [/^apps\/web\/src\/wasm\//, /\/test\/browser\/pkg\//, /\/vendor\//];

// Both bounds are load-bearing. The upper one rejects six- and eight-digit CSS
// hex colours, whose next character is itself a hex digit — `{3,}` would flag
// every `#006644`. The lower one exempts the `#NN Dn` wayfinder citations: issue
// numbers here share one ever-increasing counter with PRs, which passed 1000
// long ago, so this repo can never mint another two-digit number and a bare
// `#33` can only be FSM1/cipher-box-next. Do not lower it to `{1,`.
const NUMBER = /#\d{3,5}(?![\da-fA-F])/g;

// An `owner/repo`-qualified number names a durable decision record in another
// repo; `&#9660;` is an HTML entity and `{:#010o}` a format spec. A bare number,
// or one prefixed only by a word like `PR`, is a ticket.
const EXEMPT_PREFIX = /(?:[\w.-]+\/[\w.-]+|[&:])$/;

// This repo's own issue links rot exactly like a bare number does.
const OWN_ISSUE_URL = /github\.com\/FSM1\/cipher-box\/(?:issues|pull)\/\d+/g;

const tracked = execFileSync('git', ['ls-files', '-z', ...ROOTS], { encoding: 'utf8' })
  .split('\0')
  .filter((path) => path && EXTENSIONS.test(path) && !SKIP.some((re) => re.test(path)));

// `git ls-files` exits 0 on a pathspec that matches nothing, so a renamed root
// would silently drop out of the scan and the gate would pass vacuously.
const empty = ROOTS.filter((root) => !tracked.some((path) => path.startsWith(`${root}/`)));
if (empty.length > 0) {
  console.error(`No scannable files under: ${empty.join(', ')}. Fix ROOTS in this script.`);
  process.exit(1);
}

const offences = [];
for (const path of tracked) {
  readFileSync(path, 'utf8')
    .split('\n')
    .forEach((line, index) => {
      const found = [
        ...[...line.matchAll(NUMBER)].filter(
          ({ index: at }) => !EXEMPT_PREFIX.test(line.slice(0, at))
        ),
        ...line.matchAll(OWN_ISSUE_URL),
      ];
      for (const [token] of found) {
        offences.push({ path, line: index + 1, token, text: line.trim() });
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
      '\nis not a tracker reference, widen the exemptions above.'
  );
  // Not `process.exit`, which can truncate the list above on a piped stderr.
  process.exitCode = 1;
} else {
  console.log(`No tracking-issue references in ${tracked.length} source files.`);
}
