# @cipherbox/api-client

Typed HTTP client for the CipherBox API, generated from OpenAPI spec via orval.

## Install

```bash
pnpm add @cipherbox/api-client
```

## Usage

```typescript
import { createApiInstance } from '@cipherbox/api-client';
const api = createApiInstance({ baseURL: 'https://api.cipherbox.cc', getAccessToken: () => token });
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
