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
import { contentSecurityPolicy } from './csp.mjs';

const csp = contentSecurityPolicy(process.env);
const config = JSON.stringify({ app: { security: { csp } } });

await run([...process.argv.slice(2), '--config', config], 'tauri');
