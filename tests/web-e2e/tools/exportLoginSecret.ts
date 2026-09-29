/**
 * Exports the Web3Auth login secret of a soak wallet account (ADR 0053 D2):
 * the SIWE identity token, then Core Kit in Node through `loginWithJWT` and
 * `_UNSAFE_exportTssKey`. It prints once to stdout and writes nothing to disk.
 * Diagnostics go to stderr. The runbook is `staging/README.md`.
 */

import { fstatSync } from 'node:fs';
import { createRequire } from 'node:module';
import { text } from 'node:stream/consumers';
import {
  COREKIT_STATUS,
  MemoryStorage,
  WEB3AUTH_NETWORK,
  Web3AuthMPCCoreKit,
} from '@web3auth/mpc-core-kit';
import type { Hex } from 'viem';
import { generatePrivateKey } from 'viem/accounts';
import { walletIdentity } from '../identity';
import {
  formatLoginSecret,
  parseInvocation,
  parseWalletKey,
  readConfig,
  renderOutput,
  USAGE,
  UsageError,
  WALLET_KEY_ENV,
  type ExportConfig,
} from './loginSecretExport';

// A webpack CommonJS bundle, whose named exports Node's ESM loader cannot see.
const { tssLib } = createRequire(import.meta.url)(
  '@toruslabs/tss-dkls-lib'
) as typeof import('@toruslabs/tss-dkls-lib');

async function exportLoginSecret(walletKey: Hex, config: ExportConfig): Promise<string> {
  const credential = await walletIdentity(config.apiUrl, config.siweOrigin, walletKey);

  const coreKit = new Web3AuthMPCCoreKit({
    web3AuthClientId: config.web3AuthClientId,
    // Every web build but production signs in on DEVNET, staging included.
    web3AuthNetwork: WEB3AUTH_NETWORK.DEVNET,
    storage: new MemoryStorage(),
    manualSync: true,
    tssLib,
    uxMode: 'nodejs',
    // A session would upload the factor key and the TSS share to the session
    // server, and this process never restores one.
    disableSessionManager: true,
  });
  await coreKit.init({ handleRedirectResult: false, rehydrate: false });
  await coreKit.loginWithJWT({
    verifier: config.verifier,
    verifierId: credential.verifierId,
    idToken: credential.token,
  });
  if (coreKit.status === COREKIT_STATUS.REQUIRED_SHARE) {
    throw new Error(
      'the account carries a factor policy, so its hashed factor is gone; see "A recovery phrase locks an account" in staging/README.md'
    );
  }
  if (coreKit.status !== COREKIT_STATUS.LOGGED_IN) {
    throw new Error(`the sign-in stopped at ${coreKit.status}`);
  }
  // A first sign-in exists only in memory until it is committed.
  await coreKit.commitChanges();
  return formatLoginSecret(await coreKit._UNSAFE_exportTssKey());
}

async function main(): Promise<string | null> {
  const invocation = parseInvocation(process.argv.slice(2), process.env);
  if (invocation.kind === 'help') {
    process.stderr.write(USAGE);
    return null;
  }
  if (fstatSync(process.stdout.fd).isFile()) {
    throw new UsageError('stdout is a file; the secret goes to a terminal or a pipe only');
  }
  const config = readConfig(process.env);

  let walletKey: Hex;
  switch (invocation.source) {
    case 'stdin':
      walletKey = parseWalletKey(await text(process.stdin));
      break;
    case 'env':
      walletKey = parseWalletKey(process.env[WALLET_KEY_ENV] ?? '');
      break;
    case 'mint':
      process.stderr.write(`${WALLET_KEY_ENV} is unset: minting a fresh wallet\n`);
      walletKey = generatePrivateKey();
      break;
  }

  const loginSecret = await exportLoginSecret(walletKey, config);
  return renderOutput(loginSecret, invocation.source === 'mint' ? walletKey : undefined);
}

// Core Kit's HTTP clients hold the event loop open, so the process exits
// explicitly, and only after stdout has taken the write.
main().then(
  (output) => {
    if (output === null) process.exit(0);
    process.stdout.write(output, () => process.exit(0));
  },
  (failure: unknown) => {
    const reason = failure instanceof Error ? failure.message : 'unknown failure';
    process.stderr.write(`export-login-secret: ${reason}\n`);
    process.exit(failure instanceof UsageError ? 2 : 1);
  }
);
