# Ephemeral JWKS Keys Break Web3Auth Login After API Restart

**Date:** 2026-02-16

## Original Prompt

> Debugging `crypto/rsa: verification error` from Web3Auth `loginWithJWT` after API restart during UAT.

## What I Learned

- **Ephemeral RSA keypairs + Web3Auth JWKS caching = broken login after API restart.** When `IDENTITY_JWT_PRIVATE_KEY` is not set, `JwtIssuerService` generates a new keypair on every startup. Web3Auth's Torus nodes cache the JWKS endpoint, so the old public key is used to verify JWTs signed with the new private key. Result: `crypto/rsa: verification error`.

- **The error message is misleading.** `"unable to verify jwt token, [failed to verify jws signature]"` suggests the JWT is malformed or the signing logic is wrong. The actual issue is a key mismatch caused by infrastructure caching — the signing is perfectly correct.

- **`jose.importPKCS8()` defaults to non-extractable keys.** When loading a persistent key from env, must pass `{ extractable: true }` as the third argument, otherwise `exportJWK()` throws `"non-extractable CryptoKey cannot be exported as a JWK"`.

- **Multiline PEM doesn't work in `.env` files.** Base64-encode the PEM and decode it in the service: `Buffer.from(pemKey, 'base64').toString('utf8')`.

- **Fastest fix for JWKS cache issues: new ngrok URL.** Since Web3Auth caches per-URL, restarting ngrok gives a new URL with zero cached state. Update the verifier's JWKS endpoint on the Web3Auth dashboard and the new key is picked up immediately.

- **Local IPFS node (Kubo) runs on the Docker host, not localhost.** `IPFS_LOCAL_API_URL` must point to `192.168.133.114:5001`, not `localhost:5001`. Same host as PostgreSQL and Redis.

- **Mock IPNS routing service exists at `tools/mock-ipns-routing/`.** Set `DELEGATED_ROUTING_URL=http://localhost:3001` in API `.env` and run `pnpm --filter @cipherbox/mock-ipns-routing dev`. This avoids hitting the public DHT (`delegated-ipfs.dev`) which returns garbled records ("Unsupported wire type 4") in dev.

## What Would Have Helped

- Having `IDENTITY_JWT_PRIVATE_KEY` set in `.env` from the start (or documented in dev setup)
- A startup log warning when using ephemeral keys: "JWKS key will change on restart, Web3Auth may cache the old key"
- Knowing the IPFS host is `192.168.133.114` not `localhost` before starting UAT
- Starting the mock IPNS routing service as part of the standard dev environment

## Key Files

- `apps/api/src/auth/services/jwt-issuer.service.ts` — keypair generation + JWKS endpoint data
- `apps/api/src/auth/controllers/identity.controller.ts:65` — `GET /auth/.well-known/jwks.json` route
- `apps/api/.env` — `IDENTITY_JWT_PRIVATE_KEY`, `IPFS_PROVIDER`, `DELEGATED_ROUTING_URL`
- `apps/api/.env.example` — documents all env vars including IPFS and routing config
- `tools/mock-ipns-routing/src/index.ts` — mock delegated routing service for E2E/UAT
- `apps/web/src/lib/web3auth/hooks.ts:147` — `cipherbox-identity` verifier name used in `loginWithJWT`
