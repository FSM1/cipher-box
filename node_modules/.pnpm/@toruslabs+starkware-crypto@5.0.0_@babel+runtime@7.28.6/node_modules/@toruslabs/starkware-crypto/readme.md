# @toruslabs/starkware-crypto

[![npm version](https://badge.fury.io/js/%40toruslabs%2Fstarkware-crypto.svg)](https://badge.fury.io/js/%40toruslabs%2Fstarkware-crypto)

Signatures, keys and Pedersen hash on STARK friendly elliptic curve.

## Installation

### Bundling

This module is distributed in 3 formats:

- `main` build: `dist/lib.cjs/index.js` in CommonJS format
- `module` build: `dist/lib.esm/index.js` in ESModule format (preferred for bundlers)
- `browser` build: `dist/starkwareCrypto.umd.js` in UMD format for direct use in browsers

### Install via package manager

```bash
npm install @toruslabs/starkware-crypto
```

### Directly in Browser

CDN's serve the non-core-js polyfilled version by default.

jsdeliver

## Usage

### Signature

```ts
import { sign, verify } from '@toruslabs/starkware-crypto';

sign(keyPair, msgHash);

verify(keyPair, msgHash, signature);
```













