<!-- generated-by: gsd-doc-writer -->

# cipherbox-tee-worker

Express HTTP server that runs inside a Trusted Execution Environment to republish IPNS records on behalf of CipherBox users without ever holding plaintext keys outside the enclave.

## Security Model

The API server sends each user's `encryptedIpnsPrivateKey` (ECIES-wrapped with the current `teePublicKey`) to this worker. The worker decrypts the key inside hardware, signs the IPNS record, and immediately zeroes the plaintext from memory. The host process and CipherBox API server never see the raw IPNS private key.

See [../../docs/ARCHITECTURE.md](../../docs/ARCHITECTURE.md) for the full system architecture.

## TEE Modes

| `TEE_MODE`            | When used                         | Key derivation                              |
| --------------------- | --------------------------------- | ------------------------------------------- |
| `simulator` (default) | Local development, staging Docker | HKDF-SHA256 from a fixed seed               |
| `cvm`                 | Production — Phala Cloud CVM      | Phala dstack SDK hardware-backed derivation |

Setting `TEE_MODE=simulator` when `CIPHERBOX_ENVIRONMENT=production` (or `NODE_ENV=production`) throws at startup to prevent accidental simulator use in production.

## Key Epoch Rotation

Each `teePublicKey` is tied to a `keyEpoch` — a sequential integer that increments roughly every 4 weeks. During rotation, the worker supports a grace period by falling back to the previous epoch when decryption with the current epoch fails. This allows clients with keys encrypted under the old `teePublicKey` to continue working seamlessly. Grace-period keys are re-encrypted with the current epoch key on successful republish.

## HTTP Routes

| Method | Path               | Auth | Description                                 |
| ------ | ------------------ | ---- | ------------------------------------------- |
| GET    | `/health`          | No   | Liveness check                              |
| GET    | `/metrics`         | No   | Prometheus metrics                          |
| GET    | `/public-key`      | Yes  | `teePublicKey` for a given `keyEpoch`       |
| POST   | `/republish`       | Yes  | Batch IPNS signing                          |
| POST   | `/migrate`         | Yes  | Batch CID migration between IPFS providers  |
| POST   | `/connection-test` | Yes  | Server-side IPFS endpoint reachability test |

## Scripts

```bash
pnpm dev        # tsx watch — hot-reload development server
pnpm build      # tsc — compile to dist/
pnpm start      # node dist/index.js — run compiled output
pnpm test       # vitest run
pnpm test:watch # vitest — watch mode
```

## Environment Variables

| Variable                | Required | Default     | Description                                     |
| ----------------------- | -------- | ----------- | ----------------------------------------------- |
| `TEE_MODE`              | No       | `simulator` | `simulator` or `cvm`                            |
| `TEE_CURRENT_EPOCH`     | Yes      | —           | Active `keyEpoch` integer                       |
| `TEE_WORKER_SECRET`     | Yes      | —           | Shared secret for bearer auth                   |
| `PORT`                  | No       | `3001`      | HTTP listen port                                |
| `IPFS_GATEWAY_URL`      | No       | —           | IPFS gateway for CID migration                  |
| `CIPHERBOX_ENVIRONMENT` | No       | —           | Set to `production` to enable production guards |

See [../../docs/CONFIGURATION.md](../../docs/CONFIGURATION.md) for the full configuration reference.

## Deployment

See [../../docs/DEPLOYMENT.md](../../docs/DEPLOYMENT.md) for Docker and Phala Cloud CVM deployment instructions.
