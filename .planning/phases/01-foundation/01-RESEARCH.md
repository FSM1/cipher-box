# Phase 1: Foundation - Research

**Researched:** 2026-01-20
**Domain:** Project scaffolding, monorepo setup, CI/CD, development environment
**Confidence:** HIGH

## Summary

Phase 1 establishes the development infrastructure for CipherBox: a pnpm workspace monorepo containing NestJS backend, React frontend, and shared crypto package. The locked decisions from CONTEXT.md specify pnpm workspaces, GitHub Actions CI/CD, Docker Compose for local PostgreSQL, and Railway for deployment.

The standard approach is well-established: NestJS 11.x with TypeORM for the backend, React 18.x with Vite 7.x for the frontend, and pnpm 10.x workspaces for monorepo management. ESLint 9.x flat config with Prettier and Husky provides code quality enforcement.

**Primary recommendation:** Use the NestJS CLI (`nest new`) with `--strict` flag for backend scaffolding, and `pnpm create vite` with `react-ts` template for frontend. Configure a shared `tsconfig.base.json` at root with package-specific extensions.

## Standard Stack

The established libraries/tools for this domain:

### Core

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| pnpm | 10.28.x | Package manager & workspaces | Fastest installs, strict dependency resolution, built-in workspace support |
| NestJS | 11.1.x | Backend framework | TypeScript-first, modular architecture, strong DI container |
| React | 18.3.x | Frontend framework | Per project spec; stable concurrent features, wide ecosystem |
| Vite | 7.3.x | Frontend build tool | Fast HMR, native ESM, excellent TypeScript support |
| TypeScript | 5.9.x | Type system | Latest stable, strict mode enabled |
| TypeORM | 0.3.28 | Database ORM | NestJS integration via @nestjs/typeorm, mature migrations |
| PostgreSQL | 16.x | Database | Per project spec; ACID compliance, JSON support |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| @nestjs/typeorm | 11.0.0 | TypeORM integration | Database connection in NestJS |
| @nestjs/config | latest | Environment config | Load .env files, validate config |
| pg | latest | PostgreSQL driver | TypeORM database driver |
| class-validator | latest | DTO validation | Request validation in NestJS |
| class-transformer | latest | DTO transformation | Transform plain objects to class instances |
| react-router-dom | 7.12.x | Frontend routing | Client-side navigation |
| ESLint | 9.39.x | Linting | Code quality enforcement |
| Prettier | 3.8.x | Formatting | Consistent code style |
| Husky | 9.1.x | Git hooks | Pre-commit enforcement |
| lint-staged | latest | Staged file linting | Run linters on staged files only |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| TypeORM | Prisma | Prisma has better DX but TypeORM has better NestJS integration, more mature |
| react-router-dom | @tanstack/react-router | TanStack is newer with type-safe routes, but react-router is more established |
| pnpm workspaces | Nx | Nx adds more features but complexity; pnpm sufficient for this project size |

**Installation (root):**
```bash
# Initialize pnpm workspace
pnpm init
echo "packages:\n  - 'apps/*'\n  - 'packages/*'" > pnpm-workspace.yaml

# Install root dev dependencies
pnpm add -Dw typescript @types/node eslint prettier husky lint-staged
```

## Architecture Patterns

### Recommended Project Structure

```
cipher-box/
├── apps/
│   ├── api/                    # NestJS backend application
│   │   ├── src/
│   │   │   ├── main.ts
│   │   │   ├── app.module.ts
│   │   │   ├── app.controller.ts
│   │   │   ├── app.service.ts
│   │   │   ├── auth/           # Feature module
│   │   │   │   ├── auth.module.ts
│   │   │   │   ├── auth.controller.ts
│   │   │   │   ├── auth.service.ts
│   │   │   │   └── dto/
│   │   │   ├── vault/          # Feature module
│   │   │   ├── ipfs/           # Feature module
│   │   │   └── common/         # Shared utilities
│   │   │       ├── guards/
│   │   │       ├── pipes/
│   │   │       └── filters/
│   │   ├── test/
│   │   ├── package.json
│   │   └── tsconfig.json       # Extends root tsconfig.base.json
│   │
│   └── web/                    # React frontend application
│       ├── src/
│       │   ├── main.tsx
│       │   ├── App.tsx
│       │   ├── auth/           # Feature folder
│       │   │   ├── components/
│       │   │   ├── hooks/
│       │   │   └── services/
│       │   ├── files/          # Feature folder
│       │   ├── folders/        # Feature folder
│       │   └── shared/         # Shared components/hooks
│       ├── public/
│       ├── package.json
│       ├── tsconfig.json
│       └── vite.config.ts
│
├── packages/
│   └── crypto/                 # Shared crypto utilities
│       ├── src/
│       │   ├── index.ts
│       │   ├── aes.ts
│       │   ├── ecies.ts
│       │   └── utils.ts
│       ├── package.json
│       └── tsconfig.json
│
├── docker/
│   └── docker-compose.yml      # Local PostgreSQL
│
├── .github/
│   └── workflows/
│       └── ci.yml              # GitHub Actions CI
│
├── .husky/
│   └── pre-commit              # Pre-commit hooks
│
├── package.json                # Root package.json (workspace scripts)
├── pnpm-workspace.yaml         # Workspace configuration
├── tsconfig.base.json          # Shared TypeScript config
├── eslint.config.js            # Shared ESLint config
├── prettier.config.js          # Shared Prettier config
├── .env.example                # Environment template
└── README.md
```

### Pattern 1: pnpm Workspace Configuration

**What:** Configure pnpm to recognize workspace packages
**When to use:** Always, at project initialization

```yaml
# pnpm-workspace.yaml
packages:
  - 'apps/*'
  - 'packages/*'
```

```json
// Root package.json
{
  "name": "cipher-box",
  "private": true,
  "scripts": {
    "dev": "pnpm --parallel -r run dev",
    "build": "pnpm --parallel -r run build",
    "lint": "pnpm --parallel -r run lint",
    "test": "pnpm --parallel -r run test",
    "prepare": "husky"
  },
  "devDependencies": {
    "typescript": "^5.9.3",
    "eslint": "^9.39.2",
    "prettier": "^3.8.0",
    "husky": "^9.1.7",
    "lint-staged": "^15.0.0"
  }
}
```

### Pattern 2: Shared TypeScript Configuration

**What:** Base tsconfig extended by all packages
**When to use:** Always, ensures consistent TypeScript settings

```json
// tsconfig.base.json (root)
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "strict": true,
    "strictNullChecks": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true
  }
}
```

```json
// apps/api/tsconfig.json
{
  "extends": "../../tsconfig.base.json",
  "compilerOptions": {
    "module": "CommonJS",
    "outDir": "./dist",
    "rootDir": "./src",
    "emitDecoratorMetadata": true,
    "experimentalDecorators": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist"]
}
```

### Pattern 3: NestJS Module Organization

**What:** Feature-based module structure per NestJS best practices
**When to use:** All backend feature development

```typescript
// apps/api/src/app.module.ts
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: ['.env.local', '.env'],
    }),
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        type: 'postgres',
        host: config.get('DB_HOST', 'localhost'),
        port: config.get('DB_PORT', 5432),
        username: config.get('DB_USERNAME', 'postgres'),
        password: config.get('DB_PASSWORD', 'postgres'),
        database: config.get('DB_DATABASE', 'cipherbox'),
        autoLoadEntities: true,
        synchronize: config.get('NODE_ENV') !== 'production',
      }),
    }),
  ],
})
export class AppModule {}
```

### Pattern 4: Workspace Package Linking

**What:** Use workspace protocol for internal dependencies
**When to use:** When one package depends on another in the monorepo

```json
// apps/api/package.json
{
  "name": "@cipherbox/api",
  "dependencies": {
    "@cipherbox/crypto": "workspace:*"
  }
}
```

```json
// apps/web/package.json
{
  "name": "@cipherbox/web",
  "dependencies": {
    "@cipherbox/crypto": "workspace:*"
  }
}
```

### Anti-Patterns to Avoid

- **Hoisting sensitive dependencies:** Don't hoist crypto libraries to root; keep in specific packages for security isolation
- **Circular workspace dependencies:** Design packages to have clear dependency direction (crypto <- api, crypto <- web)
- **Mixed module systems:** Keep backend as CommonJS (NestJS requirement), frontend as ESM; shared packages should support both
- **Global npm installs:** Use `pnpm dlx` instead of global installations

## Don't Hand-Roll

Problems that look simple but have existing solutions:

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Project scaffolding | Manual file creation | `nest new` / `pnpm create vite` | Correct boilerplate, proper dependencies |
| Environment config | Custom env parser | @nestjs/config | Validation, typing, defaults |
| Request validation | Manual validation | class-validator + class-transformer | Declarative, consistent error formats |
| Health checks | Custom endpoint | @nestjs/terminus | Standard patterns, dependency checks |
| Pre-commit hooks | Manual git hooks | Husky + lint-staged | Reliable hook installation, staged-only |
| Concurrent dev | Multiple terminals | `pnpm --parallel` or concurrently | Single command, proper output |

**Key insight:** NestJS CLI and Vite scaffolding handle dozens of configuration decisions correctly. Manual setup risks missing critical configurations (decorator metadata, HMR setup, etc.).

## Common Pitfalls

### Pitfall 1: NestJS CommonJS vs ESM Mismatch

**What goes wrong:** Importing ESM-only packages into NestJS (CommonJS) causes runtime errors
**Why it happens:** NestJS uses CommonJS by default; many modern packages are ESM-only
**How to avoid:** Check package.json "type" field before adding dependencies; use dynamic imports for ESM packages
**Warning signs:** "ERR_REQUIRE_ESM" or "Cannot use import statement outside a module"

### Pitfall 2: TypeORM synchronize in Production

**What goes wrong:** `synchronize: true` in production can drop tables or corrupt data
**Why it happens:** TypeORM auto-syncs schema changes, which can be destructive
**How to avoid:** Set `synchronize: config.get('NODE_ENV') !== 'production'`; use migrations in production
**Warning signs:** Schema changes happening unexpectedly, data loss

### Pitfall 3: Workspace Dependency Resolution

**What goes wrong:** Changes to shared packages not reflected in dependent apps
**Why it happens:** pnpm caches symlinks; TypeScript may cache compiled output
**How to avoid:** Run `pnpm install` after changing shared package.json; configure tsconfig paths
**Warning signs:** "Cannot find module" errors for workspace packages

### Pitfall 4: React 18 vs React 19 Compatibility

**What goes wrong:** Installing React 19 incompatible packages with React 18 project
**Why it happens:** Many packages have peerDependency on React 19 now
**How to avoid:** Explicitly install `react@18.3.1 react-dom@18.3.1`; check peer deps
**Warning signs:** Peer dependency warnings during install

### Pitfall 5: Husky Not Running on Clone

**What goes wrong:** Git hooks don't run for team members after cloning
**Why it happens:** Husky requires `prepare` script to be run after install
**How to avoid:** Add `"prepare": "husky"` to root package.json scripts
**Warning signs:** Commits bypass linting without errors

### Pitfall 6: PostgreSQL Docker Volume Permissions

**What goes wrong:** PostgreSQL container fails to start with permission errors
**Why it happens:** Volume mount permissions differ between host and container
**How to avoid:** Use named volumes instead of bind mounts; or set correct permissions
**Warning signs:** "Permission denied" in PostgreSQL container logs

## Code Examples

Verified patterns from official sources:

### NestJS Backend Scaffolding

```bash
# Source: NestJS CLI documentation
cd apps
pnpm dlx @nestjs/cli new api --strict --skip-git --package-manager=pnpm
```

### Vite React Frontend Scaffolding

```bash
# Source: Vite documentation (vite.dev/guide)
cd apps
pnpm create vite web --template react-ts
```

### Docker Compose for PostgreSQL

```yaml
# docker/docker-compose.yml
# Source: Docker Hub postgres official image docs
services:
  postgres:
    image: postgres:16-alpine
    container_name: cipherbox-postgres
    restart: unless-stopped
    environment:
      POSTGRES_USER: ${DB_USERNAME:-postgres}
      POSTGRES_PASSWORD: ${DB_PASSWORD:-postgres}
      POSTGRES_DB: ${DB_DATABASE:-cipherbox}
    ports:
      - "${DB_PORT:-5432}:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 5s
      timeout: 5s
      retries: 5

volumes:
  postgres_data:
```

### GitHub Actions CI Workflow

```yaml
# .github/workflows/ci.yml
# Source: GitHub Actions documentation
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
        with:
          version: 10
      - uses: actions/setup-node@v4
        with:
          node-version: '22'
          cache: 'pnpm'
      - run: pnpm install --frozen-lockfile
      - run: pnpm lint

  test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16-alpine
        env:
          POSTGRES_USER: postgres
          POSTGRES_PASSWORD: postgres
          POSTGRES_DB: cipherbox_test
        ports:
          - 5432:5432
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
        with:
          version: 10
      - uses: actions/setup-node@v4
        with:
          node-version: '22'
          cache: 'pnpm'
      - run: pnpm install --frozen-lockfile
      - run: pnpm test
        env:
          DB_HOST: localhost
          DB_PORT: 5432
          DB_USERNAME: postgres
          DB_PASSWORD: postgres
          DB_DATABASE: cipherbox_test

  build:
    runs-on: ubuntu-latest
    needs: [lint, test]
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
        with:
          version: 10
      - uses: actions/setup-node@v4
        with:
          node-version: '22'
          cache: 'pnpm'
      - run: pnpm install --frozen-lockfile
      - run: pnpm build
```

### ESLint Flat Config

```javascript
// eslint.config.js (root)
// Source: ESLint documentation (eslint.org)
import globals from 'globals';
import pluginJs from '@eslint/js';
import tseslint from 'typescript-eslint';
import pluginPrettier from 'eslint-plugin-prettier/recommended';

export default [
  { ignores: ['**/dist/**', '**/node_modules/**'] },
  { files: ['**/*.{js,mjs,cjs,ts,tsx}'] },
  { languageOptions: { globals: { ...globals.browser, ...globals.node } } },
  pluginJs.configs.recommended,
  ...tseslint.configs.recommended,
  pluginPrettier,
  {
    rules: {
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      '@typescript-eslint/explicit-function-return-type': 'off',
      '@typescript-eslint/no-explicit-any': 'warn',
    },
  },
];
```

### Husky Pre-commit Hook

```bash
# .husky/pre-commit
# Source: Husky documentation (typicode.github.io/husky)
pnpm lint-staged
```

```json
// Root package.json (partial)
{
  "lint-staged": {
    "*.{ts,tsx,js,jsx}": [
      "eslint --fix",
      "prettier --write"
    ],
    "*.{json,md,yml,yaml}": [
      "prettier --write"
    ]
  }
}
```

### NestJS Health Check Endpoint

```typescript
// apps/api/src/health/health.controller.ts
// Source: NestJS terminus documentation
import { Controller, Get } from '@nestjs/common';
import { HealthCheck, HealthCheckService, TypeOrmHealthIndicator } from '@nestjs/terminus';

@Controller('health')
export class HealthController {
  constructor(
    private health: HealthCheckService,
    private db: TypeOrmHealthIndicator,
  ) {}

  @Get()
  @HealthCheck()
  check() {
    return this.health.check([
      () => this.db.pingCheck('database'),
    ]);
  }
}
```

### Pinata SDK Setup (Backend)

```typescript
// apps/api/src/ipfs/pinata.service.ts
// Source: Pinata documentation (docs.pinata.cloud)
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PinataSDK } from 'pinata';

@Injectable()
export class PinataService {
  private pinata: PinataSDK;

  constructor(private config: ConfigService) {
    this.pinata = new PinataSDK({
      pinataJwt: this.config.getOrThrow('PINATA_JWT'),
      pinataGateway: this.config.get('PINATA_GATEWAY'),
    });
  }

  async uploadFile(file: Buffer, name: string): Promise<string> {
    const result = await this.pinata.upload.public.file(
      new File([file], name)
    );
    return result.cid;
  }

  async getFile(cid: string): Promise<Buffer> {
    const response = await this.pinata.gateways.public.get(cid);
    return Buffer.from(await response.arrayBuffer());
  }
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| ESLint .eslintrc.js | ESLint flat config (eslint.config.js) | ESLint 9.x (2024) | New config format, plugin import syntax |
| NestJS 10 ConsoleLogger | NestJS 11 enhanced logger | NestJS 11 (2025) | Better nested object formatting, JSON support |
| TypeORM keepConnectionAlive | Removed in @nestjs/typeorm 11 | 2025 | Use connection pooling instead |
| React 18 propTypes | Removed in React 19 | 2024 | Use TypeScript types instead |
| Husky v4 hooks | Husky v9 shell scripts | 2023+ | Simpler .husky/ directory structure |

**Deprecated/outdated:**
- **uuid package in NestJS:** Replaced by native `crypto.randomUUID()` in @nestjs/typeorm 11
- **ESLint legacy config:** .eslintrc.* files deprecated in favor of flat config
- **React propTypes:** Silently ignored in React 19; use TypeScript

## Open Questions

Things that couldn't be fully resolved:

1. **React 18 vs React 19 for new project**
   - What we know: Project spec says React 18; React 19 is current stable (19.2.3)
   - What's unclear: Whether to stick with React 18 or upgrade spec
   - Recommendation: Stick with React 18.3.1 as per spec; it's stable and avoids breaking changes

2. **Shared crypto package module format**
   - What we know: NestJS uses CommonJS, Vite uses ESM
   - What's unclear: Best approach for dual-format shared package
   - Recommendation: Use TypeScript with both CJS and ESM outputs; configure package.json exports field

3. **Railway auto-deploy configuration**
   - What we know: Railway supports GitHub integration and env var injection
   - What's unclear: Exact setup for monorepo with multiple deployable apps
   - Recommendation: Research Railway Nixpacks or Dockerfile approach during implementation

## Sources

### Primary (HIGH confidence)
- NestJS CLI documentation - Project scaffolding commands
- Vite documentation (vite.dev/guide) - React TypeScript template
- pnpm documentation (pnpm.io/workspaces) - Workspace configuration
- ESLint documentation - Flat config format
- Pinata documentation (docs.pinata.cloud) - SDK setup

### Secondary (MEDIUM confidence)
- [NestJS TypeORM PostgreSQL setup guide](https://medium.com/@gausmann.simon/nestjs-typeorm-and-postgresql-full-example-development-and-project-setup-working-with-database-c1a2b1b11b8f) - Verified with official docs
- [pnpm monorepo setup guide](https://jsdev.space/complete-monorepo-guide/) - Verified with pnpm.io
- [GitHub Actions monorepo CI/CD guide](https://dev.to/pockit_tools/github-actions-in-2026-the-complete-guide-to-monorepo-cicd-and-self-hosted-runners-1jop) - Recent 2026 guide
- [Railway NestJS deployment](https://docs.railway.com/guides/nest) - Official Railway docs

### Tertiary (LOW confidence - verify during implementation)
- Exact Railway monorepo configuration needs validation
- ESM/CJS dual-format shared package exports need testing

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - Versions verified via npm, patterns from official docs
- Architecture: HIGH - Based on NestJS and pnpm official recommendations
- Pitfalls: HIGH - Common issues documented across multiple sources
- Railway deployment: MEDIUM - Official docs exist but monorepo specifics less documented

**Research date:** 2026-01-20
**Valid until:** 2026-02-20 (30 days - stable technologies)

---

*Phase: 01-foundation*
*Research completed: 2026-01-20*
