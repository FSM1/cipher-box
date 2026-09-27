# Can a Node script export the login secret of a wallet account from Core Kit?

Research for [soak: can a Node script drive Core Kit to export the login secret of a wallet account (#2048)](https://github.com/FSM1/cipher-box/issues/2048), under the map [#2047](https://github.com/FSM1/cipher-box/issues/2047).

Sources: code on `main` at `65b2af75c`; the installed `@web3auth/mpc-core-kit@3.5.0`, `@tkey/tss@15.1.0`, `@toruslabs/customauth@20.4.0` and `@toruslabs/tss-dkls-lib@4.1.0` from the lockfile; the upstream [Web3Auth/mpc-core-kit](https://github.com/Web3Auth/mpc-core-kit) tests; the official [Node quick-start](https://github.com/Web3Auth/web3auth-core-kit-examples/tree/main/mpc-core-kit-node/mpc-core-kit-node-quick-start); and one live probe against staging on 2026-09-27. Paths in `dist/` are relative to the package root in `node_modules`.

## Verdict

**YES. A Node script is feasible, and a live probe proved it.**

On 2026-09-27 a throwaway Node 22 script ran the full chain against `https://api-staging.cipherbox.cc` and the staging verifier `cipherbox-identity` on Sapphire DEVNET. It used a fresh random wallet key. The chain was: SIWE challenge, SIWE signature, `POST /auth/identity/wallet`, `loginWithJWT`, `commitChanges`, `_UNSAFE_exportTssKey`. The script then did a second, independent login with the same wallet key. The output was:

```text
[fresh] identity token ok, verifierId length 36
[fresh] after init INITIALIZED
[fresh] after loginWithJWT LOGGED_IN
[fresh] export: 64 lowercase hex chars = true
[again] identity token ok, verifierId length 36
[again] after init INITIALIZED
[again] after loginWithJWT LOGGED_IN
[again] export: 64 lowercase hex chars = true
same secret across two logins = true
same tss pub across two logins = true
```

The probe printed no secret. It lives outside the repo and is not committed.

## 1. Core Kit runs in Node

- Core Kit declares a Node mode. `CoreKitMode = UX_MODE_TYPE | "nodejs" | "react-native"` (`dist/types/interfaces.d.ts`).
- In `"nodejs"` mode the constructor does not read `window`. It sets `baseUrl` to `https://localhost` (`dist/lib.cjs/mpcCoreKit.js`, constructor). `loginWithOAuth` refuses the mode, and `loginWithJWT` does not (`mpcCoreKit.js`, `loginWithOAuth`, `isNodejsOrRN`).
- `init()` reads `window.location.hash` only when `uxMode === "redirect"`. In `"nodejs"` mode the check short-circuits, and `torusSp.init` does not run (`mpcCoreKit.js`, `init`). Pass `init({ handleRedirectResult: false, rehydrate: false })` to make this explicit.
- Storage: the `storage` option takes any `IStorage` or `IAsyncStorage` (`interfaces.d.ts`, `Web3AuthOptions.storage`). The package exports `MemoryStorage` (`dist/lib.cjs/index.js`, `helper/browserStorage.js`). No `localStorage` or `indexedDB` is necessary.
- Globals: `init()` calls the global `fetch` for the feature-access check (`mpcCoreKit.js`, `featureRequest`). Node 18 and later have `fetch`. `navigator` is read only in `enableMFA` outside Node mode (`mpcCoreKit.js`, `enableMFA`). The export path does not call `enableMFA`.
- The TSS library: the constructor reads `tssLib.keyType` only. The DKLS WASM loads only in `precompute_secp256k1` and `sign` (`mpcCoreKit.js`, `loadTssWasm` callers). The export does not sign, so no WASM runs. `@toruslabs/tss-dkls-lib` is a CommonJS module with the WASM inline, and it imports in Node without side effects (`dist/tssDklsLib.cjs.js`).
- DEVNET: `WEB3AUTH_NETWORK.DEVNET` is `sapphire_devnet` (`dist/lib.cjs/constants.js`). The web app picks DEVNET for every environment that is not `production` (`apps/web/src/auth/coreKit.ts`, `createCoreKitSession`). Staging builds with `VITE_ENVIRONMENT: staging` (`.github/workflows/deploy-staging.yml`), so staging is DEVNET.
- Upstream evidence: the Core Kit test suite runs under `node --test` with `uxMode: "nodejs"`, `WEB3AUTH_NETWORK.DEVNET` and `MemoryStorage` (`package.json` `scripts.test`; upstream `tests/login.spec.ts`). Upstream `tests/importRecovery.spec.ts` calls `_UNSAFE_exportTssKey` in that mode. The official Node quick-start uses `uxMode: "nodejs"`, `manualSync: true` and `tssLib` from `@toruslabs/tss-dkls-lib`.

## 2. `loginWithJWT` works with a bare JWT

- `loginWithJWT` sends the token straight to the Torus nodes: `customAuthInstance.getTorusKey(verifier, verifierId, { verifier_id }, idToken, …)` (`mpcCoreKit.js`, `loginWithJWT`). `getTorusKey` fetches node details and calls `torus.retrieveShares` (`@toruslabs/customauth` `dist/lib.cjs/login.js`). No step reads a browser session, a cookie, or a popup.
- The token must be fresh. The API mints it with a 300-second lifetime (`apps/api/src/auth/services/identity-token.service.ts`, `TOKEN_TTL_SECONDS`). Mint one token for each login and use it at once.
- The token comes from the API with no browser. `POST /auth/siwe/challenge` returns `{ nonce }` (`apps/api/src/auth/auth.controller.ts`, `siweChallenge`). `POST /auth/identity/wallet` takes `{ message, signature }` and returns `{ token, verifierId, email, expiresAt }` (`apps/api/src/auth/identity.controller.ts`, `wallet`; `dto/auth.dto.ts`, `SiweLoginRequestDto`).
- The SIWE checks are on the message fields only. The API accepts a message whose `domain` is the host of an origin in `CORS_ALLOWED_ORIGINS`, whose `nonce` is the issued one, and whose `statement` is `Sign in to CipherBox encrypted storage` (`apps/api/src/auth/services/siwe.service.ts`). The API does not check an `Origin` header. The staging `CORS_ALLOWED_ORIGINS` includes `https://app-staging.cipherbox.cc` and `http://localhost:5173` (GitHub environment `staging`, variable `CORS_ALLOWED_ORIGINS`).
- Build the message as the web app does: `createSiweMessage` from `viem/siwe` with `chainId` 1, `version` `'1'`, `domain` and `uri` from an allowed origin (`apps/web/src/components/auth/WalletSignature.tsx`). Sign it with `privateKeyToAccount(key).signMessage` from `viem/accounts`, as the staging suite does (`tests/web-e2e/staging/wallet.ts`).
- `createIdentityExchange` in `@cipherbox/login` wraps both calls with the global `fetch` and nothing else (`packages/login/src/identity.ts`). A Node script can import it.

## 3. What the export needs

- `_UNSAFE_exportTssKey` needs three things in state: key type secp256k1, `state.factorKey`, and `state.signatures` (`mpcCoreKit.js`, `_UNSAFE_exportTssKey`). `tssLib` from `@toruslabs/tss-dkls-lib` gives secp256k1. `loginWithJWT` sets the signatures. The login sets `factorKey` when it reaches `COREKIT_STATUS.LOGGED_IN`.
- A fresh account needs no factor. With no metadata, `setupTkey` calls `handleNewUser`, which creates the key under the hashed factor derived from the postbox key and the client id (`mpcCoreKit.js`, `setupTkey`, `handleNewUser`). The status is then `LOGGED_IN`. The probe confirmed this.
- `enableMFA` is not necessary. It is also not wanted: it deletes the hashed factor (`mpcCoreKit.js`, `enableMFA`), and a Node login after it stops at `REQUIRED_SHARE`.
- An account that already has a factor policy (a recovery phrase) stops at `REQUIRED_SHARE`, because the hashed factor is gone (`mpcCoreKit.js`, `handleExistingUser`). The script then needs the phrase: `inputFactorKey(new BN(mnemonicToKey(phrase), 'hex'))`, as the web recovery does (`apps/web/src/auth/coreKit.ts`, `recoverWithPhrase`). Use a soak account with no factor policy.
- With `manualSync: true`, call `commitChanges()` after the login and before the export, as the web app does (`apps/web/src/auth/coreKit.ts`, `login`). Otherwise a fresh account exists only in local memory.
- The export changes the account for a short time. `@tkey/tss` adds a temporary factor with a share refresh, interpolates the key, and then deletes the temporary factor (`@tkey/tss` `dist/lib.cjs/tss.js`, `_UNSAFE_exportTssKey`). The TSS key does not change, and the probe got the same secret from two logins.
- The Node secret is the browser secret for the same wallet, by construction. The key is a function of the client id, the network, the verifier, the `verifierId`, and the hashed-factor nonce (`mpcCoreKit.js`, constructor and `handleNewUser`). The web app sets no `hashedFactorNonce` and no `useDKG`, so the defaults apply on both hosts (`apps/web/src/auth/coreKit.ts`, `createCoreKitSession`). The API gives one wallet one stable `verifierId` (ADR 0039 D1). The probe did not compare against a browser login.
- The output is 64 lowercase hex characters (`FIELD_ELEMENT_HEX_LEN`), which is the 32-byte scalar `exportLoginSecret` requires (`packages/login/src/secret.ts`, `LOGIN_SECRET_LEN`).
- The script creates the Web3Auth side of an account only. It does not create the CipherBox API account or the vault. The engine does that when it starts with the secret.

## 4. The Playwright fallback cost

The fallback is not necessary. Its cost, for the record:

- The introspection hook takes a secret in (`signIn(loginSecretHex, accountId)`) and has no tap that gives one out (`apps/web/src/engine/introspection.ts`, `EngineIntrospection`). The fallback needs a new hook tap that exports the root secret from the page. That is a security-relevant app change with its own review gates.
- A deployed build refuses `VITE_E2E_HOOK` (`apps/web/vite.config.ts`; `apps/web/src/engine/config.ts`, `shipsE2eHook`). So the fallback needs a local build with the hook, the staging API URL, and the staging client id and verifier. That build needs the engine WASM build first.
- The page must serve from an allowed origin, for example `http://localhost:5173`, because the SIWE domain must be in the staging `CORS_ALLOWED_ORIGINS`.
- The run then needs a Playwright browser, `installTestWallet` (`tests/web-e2e/staging/wallet.ts`), and the full wallet picker flow in the UI.
- Estimate: one extra app change under review, a WASM plus Vite build per run, and a browser dependency. The Node script needs none of these.

## 5. Recommended script skeleton

Home: `scripts/` at the root holds `.mjs` files, and the root `typecheck` is `pnpm -r run typecheck`, so no package typechecks root `scripts/`. Put the script in a workspace package with a `typecheck` script. `tools/perf` fits a soak harness (`tsx`, `tsc --noEmit`). `tests/web-e2e` also fits, and it already depends on `viem` and `@cipherbox/login`. Add `@web3auth/mpc-core-kit` and `@toruslabs/tss-dkls-lib` at the versions `apps/web` uses.

Steps:

1. Read the wallet private key from an environment variable or a file. Do not take it as a command-line argument.
2. Read the API base URL, the Web3Auth client id and the verifier name from the environment. The staging values are the GitHub `vars` `API_URL`, `VITE_WEB3AUTH_CLIENT_ID` and `VITE_WEB3AUTH_VERIFIER`.
3. `const exchange = createIdentityExchange(apiUrl)`; `const nonce = await exchange.walletNonce()`.
4. Build the SIWE message with `createSiweMessage`: the wallet address, `chainId: 1`, `version: '1'`, `domain: 'app-staging.cipherbox.cc'`, `uri: 'https://app-staging.cipherbox.cc'`, the nonce, and the statement `Sign in to CipherBox encrypted storage`.
5. Sign it with `privateKeyToAccount(key).signMessage({ message })`.
6. `const credential = await exchange.fromWalletSignature(message, signature)`.
7. Construct `Web3AuthMPCCoreKit` with `web3AuthClientId`, `web3AuthNetwork: WEB3AUTH_NETWORK.DEVNET`, `storage: new MemoryStorage()`, `manualSync: true`, `tssLib`, `uxMode: 'nodejs'`, and `sessionTime` equal to the web value (8 hours). Optionally set `disableSessionManager: true`, because the script does not restore a session.
8. `await coreKit.init({ handleRedirectResult: false, rehydrate: false })`.
9. `await coreKit.loginWithJWT({ verifier, verifierId: credential.verifierId, idToken: credential.token })`.
10. If the status is `REQUIRED_SHARE`, stop with an error that names the factor policy. If the status is not `LOGGED_IN`, stop with the status.
11. `await coreKit.commitChanges()`.
12. Call `_UNSAFE_exportTssKey()` and check the result against `/^[0-9a-f]{64}$/`. `exportLoginSecret` from `@cipherbox/login` does the same check and returns the bytes, if the script wraps Core Kit in a `LoginSecretExporter`.
13. Print the hex once to stdout, with no label and no log line around it. Print diagnostics to stderr only.
14. Exit the process explicitly: Core Kit and its HTTP clients can keep the event loop alive.

## Residuals

- The probe did not compare the Node secret with a browser export for the same wallet. The argument in section 3 is from the source. A one-time check against the staging E2E wallet flow would close it.
