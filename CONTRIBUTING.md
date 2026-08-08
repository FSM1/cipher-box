<!-- generated-by: gsd-doc-writer -->

# Contributing to CipherBox

See the "Getting started" section of the root [README.md](README.md) for prerequisites, the local
stack, and first-run instructions.

## Branch Conventions

Never push directly to `main`. All changes must go through feature branches and pull requests.

Branch naming prefixes:

- `feat/` — new features
- `fix/` — bug fixes
- `docs/` — documentation updates
- `refactor/` — code refactoring
- `chore/` — maintenance tasks

## Commit Messages

Commits must follow [Conventional Commits](https://www.conventionalcommits.org/) format:

```text
type(optional-scope): description
```

Valid types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`.

Two rules that CI enforces and will reject:

- **PR title must match the Conventional Commits pattern** — validated by `.github/workflows/pr-title.yml`
  on every open/edit/sync event.
- **No parenthesized text in the subject line** — e.g., `feat: add export (zip format)` is rejected.
  Release Please misparses parentheses as a malformed scope, causing silent release failures.
  Use dashes or brackets instead: `feat: add export - zip format` or `feat: add export [zip]`.

Local commitlint runs via lint-staged but the `commit-msg` husky hook is currently an Entire CLI
wrapper and does **not** run commitlint locally. Follow the format regardless — CI will reject
non-conforming PR titles.

## Pull Request Process

- Open a PR from your feature branch against `main`.
- The PR title must satisfy the Conventional Commits pattern above (CI checks it automatically).
- Ensure all CI checks pass: lint, type-check, and unit tests all run on every PR targeting `main`.
- Request review from a maintainer; PRs require at least one approval before merging.

## Coding Standards

Lint-staged enforces the following on every commit:

| File type                        | Tools applied                                           |
| -------------------------------- | ------------------------------------------------------- |
| `*.ts`, `*.tsx`, `*.js`, `*.jsx` | ESLint (auto-fix), Prettier                             |
| `*.json`, `*.yml`, `*.yaml`      | Prettier                                                |
| `*.md`                           | markdownlint (auto-fix, ignores `.planning/`), Prettier |

Run checks manually:

```bash
pnpm lint        # ESLint across all packages
pnpm lint:fix    # ESLint with auto-fix
pnpm lint:md     # markdownlint across all *.md files
```

Markdownlint is strict — common violations to avoid:

- Use proper `##` headings; never use `**bold text**` as a heading substitute (MD036).
- Always include blank lines before and after fenced code blocks and lists (MD031/MD032).

## API Changes

When modifying `apps/api` — DTOs, controllers, or entities — regenerate the typed client before
committing:

```bash
pnpm api:generate
```

This regenerates `packages/api-client/src/generated/`, `packages/api-client/src/models/`, and
`packages/api-client/openapi.json`. Stage these files alongside your API changes.

A pre-commit hook (`scripts/check-api-client.sh`) blocks commits where API source files are staged
but the generated `packages/api-client/openapi.json` has unstaged changes.

## Testing

See [docs/TESTING.md](docs/TESTING.md) for how to run the test suite and coverage requirements.

## License

By contributing, you agree that your contributions will be licensed under the
[MIT License](LICENSE).
