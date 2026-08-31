/**
 * One headless desktop instance: its own home, its own mount, its own control
 * endpoint.
 *
 * The mount point is `<home>/CipherBox` and the shell offers no override, so a
 * per-process home is what separates two instances of one host
 * (blueprint/desktop.md, "FS projection").
 */

import { execFile, spawn, type ChildProcess } from 'node:child_process';
import { createWriteStream } from 'node:fs';
import { mkdir, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import {
  quit,
  readEndpoint,
  refresh as sendRefresh,
  status as readStatus,
  type ControlEndpoint,
  type VaultStatus,
} from './control';
import { poll } from './poll';
import type { Deadlines } from './profile';

const run = promisify(execFile);
const LOG_TAIL_LINES = 40;

export interface InstanceOptions {
  /** Names the instance in every message and log file. */
  name: string;
  /** The per-process home. It becomes `HOME` and `USERPROFILE`. */
  home: string;
  /** The 32-byte login secret as 64 lowercase hex characters. */
  devKey: string;
  /** The `e2e-hook` build of `cipherbox-desktop`. */
  binary: string;
  logDir: string;
  deadlines: Deadlines;
}

/** The child and how it ended, so every wait can give up on a dead process. */
interface Shell {
  child: ChildProcess;
  exit: { code: number | null; signal: string | null } | null;
  logPath: string;
}

export class Instance {
  readonly name: string;
  readonly mountRoot: string;

  constructor(
    name: string,
    mountRoot: string,
    private readonly shell: Shell,
    private readonly endpoint: ControlEndpoint,
    private readonly budget: Deadlines
  ) {
    this.name = name;
    this.mountRoot = mountRoot;
  }

  status(): Promise<VaultStatus> {
    return readStatus(this.endpoint, this.budget.refreshMs);
  }

  /** The nocache manual refresh — the deterministic barrier between clients. */
  refresh(): Promise<void> {
    return sendRefresh(this.endpoint, this.budget.refreshMs);
  }

  /** Polls the status until `accept` holds, and names what the wait proves. */
  waitFor(
    what: string,
    accept: (status: VaultStatus) => boolean,
    timeoutMs: number
  ): Promise<VaultStatus> {
    return poll(() => liveStatus(this.shell, this), accept, {
      what: `${this.name}: ${what}`,
      timeoutMs,
      intervalMs: this.budget.intervalMs,
    });
  }

  /** Ends the instance, and never leaves a mount for the next scenario. */
  async stop(): Promise<void> {
    if (this.shell.exit) return;
    try {
      await quit(this.endpoint, this.budget.shutdownMs);
    } catch {
      // A shell that cannot answer still has to go. The kill below takes it.
    }
    try {
      await poll(
        () => this.shell.exit !== null,
        (gone) => gone,
        {
          what: `${this.name} to exit after quit`,
          timeoutMs: this.budget.shutdownMs,
          intervalMs: this.budget.intervalMs,
        }
      );
    } catch {
      this.shell.child.kill('SIGKILL');
      await forceUnmount(this.mountRoot);
    }
  }
}

/**
 * Starts an instance and returns once its mount is live.
 *
 * A `refused` mount fails at once with its reason. A wait on a refusal only trades
 * a clear cause for a timeout.
 */
export async function startInstance(options: InstanceOptions): Promise<Instance> {
  const { name, home, binary, devKey, logDir, deadlines: budget } = options;
  const mountRoot = join(home, 'CipherBox');

  await mkdir(home, { recursive: true });
  await mkdir(logDir, { recursive: true });
  // `prepare()` refuses a mount point that already holds anything.
  await rm(mountRoot, { recursive: true, force: true });

  const controlFile = join(home, 'control');
  await rm(controlFile, { force: true });

  const logPath = join(logDir, `${name}.log`);
  const log = createWriteStream(logPath);
  const child = spawn(binary, ['--dev-key-stdin', '--control-file', controlFile], {
    env: { ...process.env, HOME: home, USERPROFILE: home },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  // The key crosses on standard input. An argument would put a live login
  // secret in the process argument vector, which every local user can read.
  child.stdin?.end(`${devKey}\n`);
  child.stdout?.pipe(log);
  child.stderr?.pipe(log);

  const shell: Shell = { child, exit: null, logPath };
  child.on('exit', (code, signal) => {
    shell.exit = { code, signal };
  });
  child.on('error', (error) => {
    shell.exit = { code: null, signal: error.message };
  });

  const endpoint = await poll(
    async () => {
      await refuseIfDead(shell, name);
      return readEndpoint(controlFile);
    },
    (found): found is ControlEndpoint => found !== null,
    {
      what: `${name} to write its control file at ${controlFile}`,
      timeoutMs: budget.controlFileMs,
      intervalMs: budget.intervalMs,
    }
  );

  const instance = new Instance(name, mountRoot, shell, endpoint, budget);

  await instance.waitFor(
    `the mount to open at ${mountRoot}`,
    (status) => {
      if (status.mount.state === 'refused') {
        throw new Error(`${name} refused to mount: ${status.mount.reason}`);
      }
      return status.mount.state === 'mounted';
    },
    budget.mountMs
  );

  return instance;
}

async function liveStatus(shell: Shell, instance: Instance): Promise<VaultStatus> {
  await refuseIfDead(shell, instance.name);
  return instance.status();
}

async function refuseIfDead(shell: Shell, name: string): Promise<void> {
  if (!shell.exit) return;
  const tail = await tailOf(shell.logPath);
  throw new Error(
    `${name} exited (code ${shell.exit.code}, signal ${shell.exit.signal}). ` +
      `Its log tail:\n${tail}`
  );
}

async function tailOf(path: string): Promise<string> {
  try {
    const text = await readFile(path, 'utf8');
    return text.split('\n').slice(-LOG_TAIL_LINES).join('\n');
  } catch {
    return '(no log)';
  }
}

/** Best effort: the kernel can keep the mount after a killed shell. */
async function forceUnmount(mountRoot: string): Promise<void> {
  const tool =
    process.platform === 'darwin'
      ? { command: 'diskutil', args: ['unmount', 'force', mountRoot] }
      : process.platform === 'linux'
        ? { command: 'fusermount3', args: ['-u', mountRoot] }
        : null;
  if (!tool) return;
  try {
    await run(tool.command, tool.args);
  } catch {
    // The mount was already gone, or the tool is absent on this host.
  }
}
