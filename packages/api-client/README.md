<!-- generated-by: gsd-doc-writer -->

# @cipherbox/api-client

Typed HTTP client for the CipherBox API, generated from OpenAPI spec via orval.

This is a private internal package consumed by other packages in the monorepo. It is not published to npm.

## Usage

```typescript
import { setApiClientConfig, ipnsControllerResolveRecord } from '@cipherbox/api-client';

// Configure once at startup
setApiClientConfig({ baseUrl: 'https://api.cipherbox.cc', getAccessToken: async () => token });

// Then call generated functions directly
const result = await ipnsControllerResolveRecord({ ipnsName: 'k51...' });
```

`setApiClientConfig` accepts an optional second argument — a pre-built `AxiosInstance` — for consumers that need to share one instance between the singleton path and instance-scoped callers.

You can also use `createAxiosInstance(config)` to create an isolated axios instance (with its own interceptors) without touching the module-level singleton.

## Regenerating the client

After changing API endpoints, DTOs, or controllers, regenerate from the monorepo root:

```bash
pnpm api:generate
```

This regenerates `src/generated/` from the OpenAPI spec and rebuilds the package. Commit the updated files alongside any API changes — the pre-commit hook enforces this.

## Architecture

```text
@cipherbox/crypto
    ^
@cipherbox/core    @cipherbox/api-client  <-- You are here
    ^                    ^
@cipherbox/sdk-core <----+
    ^
@cipherbox/sdk
```

## License

ISC
