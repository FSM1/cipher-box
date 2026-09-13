#!/usr/bin/env node
/**
 * The Tauri CLI, with this build's CSP merged in.
 *
 * The committed `tauri.conf.json` cannot name the API origin: it is a
 * deployment variable, and a policy that guessed it would refuse the identity
 * exchange in exactly the builds nobody runs from source. So the policy is
 * computed here, from the same environment the bundle is built with, and
 * handed to the CLI — which reads its config before it runs the frontend
 * build, so no `beforeBuildCommand` could have supplied it.
 */

import { run } from '@tauri-apps/cli';
import { engineBuildEnv } from './buildEnv.mjs';
import { contentSecurityPolicy } from './csp.mjs';

// Resolved into this process's environment, which the CLI's children — cargo
// and the frontend build — inherit, so the compiled engine and the bundle name
// the same API as the policy below admits.
Object.assign(process.env, engineBuildEnv(process.env));

const csp = contentSecurityPolicy(process.env);
const config = JSON.stringify({ app: { security: { csp } } });

// Everything after `--` is cargo's, and cargo has a `--config` of its own that
// takes TOML dotted keys, so the JSON must land before the separator.
const args = process.argv.slice(2);
const separator = args.indexOf('--');
const own = separator === -1 ? args : args.slice(0, separator);
const cargo = separator === -1 ? [] : args.slice(separator);

await run([...own, '--config', config, ...cargo], 'tauri');
