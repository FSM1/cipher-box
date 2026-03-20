# @cipherbox/api-client

Typed HTTP client for the CipherBox API, generated from OpenAPI spec via orval.

## Install

```bash
pnpm add @cipherbox/api-client
```

## Usage

```typescript
import { setApiClientConfig, ipnsControllerResolveRecord } from '@cipherbox/api-client';

// Configure once at startup
setApiClientConfig({ baseUrl: 'https://api.cipherbox.cc', getAccessToken: async () => token });

// Then call generated functions directly
const result = await ipnsControllerResolveRecord({ ipnsName: 'k51...' });
```

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
