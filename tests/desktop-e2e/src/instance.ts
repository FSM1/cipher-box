/**
 * One headless desktop instance: its own home, its own mount, its own control
 * endpoint.
 *
 * The shell offers no mount-point override, so a per-process home is what
 * separates two instances of one host (blueprint/desktop.md, "FS projection").
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
  signIn as sendSignIn,
  signOut as sendSignOut,
  status as readStatus,
  statusOrPending,
  type ControlEndpoint,
  type MountStatus,
  type VaultStatus,
} from './control';
import { poll } from './poll';
import type { Deadlines } from './profile';

const run = promisify(execFile);
const LOG_TAIL_LINES = 40;
/** The mount point the shell picks under a given home. */
const DEFAULT_MOUNT_NAME = 'CipherBox';
/**
 * How long the unmount tool is given. A scenario that ran out of time waits for
 * this before it reports, so an unmount that never returns must not become the
 * scenario's own wait.
 */
const UNMOUNT_WITHIN_MS = 30_000;

/** Moves the data directory of an `e2e-hook` build. */
export const DATA_DIR_ENV = 'CIPHERBOX_E2E_DATA_DIR';

const DATA_LOCAL = /^e2e: home=.* data_local=(.*)$/m;

/** The data directory the shell announced on its log, or `null` before the line. */
export function announcedDataDir(log: string): string | null {
  return DATA_LOCAL.exec(log)?.[1]?.replace(/\r$/, '') ?? null;
}

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
  private wasAbandoned = false;

  constructor(
    readonly name: string,
    /** The path the shell reported once it mounted. */
    readonly mountRoot: string,
    private readonly shell: Shell,
    private readonly endpoint: ControlEndpoint,
    private readonly budget: Deadlines
  ) {}

  status(): Promise<VaultStatus> {
    return readStatus(this.endpoint, this.budget.refreshMs);
  }

  /** The nocache manual refresh — the deterministic barrier between clients. */
  refresh(): Promise<void> {
    return sendRefresh(this.endpoint, this.budget.refreshMs);
  }

  /** Signs out and leaves the shell running. */
  signOut(): Promise<void> {
    return sendSignOut(this.endpoint, this.budget.shutdownMs);
  }

  /** Signs in again in the same process, and returns once the mount is live. */
  async signIn(): Promise<void> {
    await sendSignIn(this.endpoint, this.budget.mountMs);
    const mount = await poll(
      async () => (await this.status()).mount,
      (opened) => opened.state !== 'opening',
      {
        what: `${this.name}: the mount to open after the sign-in`,
        timeoutMs: this.budget.mountMs,
        intervalMs: this.budget.intervalMs,
      }
    );
    if (mount.state === 'refused') {
      throw new Error(`${this.name} refused to mount after the sign-in: ${mount.reason}`);
    }
  }

  /** The processes this shell started that the process table still lists. */
  async children(): Promise<ChildProcessRow[]> {
    const pid = this.shell.child.pid;
    if (process.platform === 'win32' || pid === undefined) return [];
    const { stdout } = await run('ps', ['-A', '-o', 'pid=,ppid=,stat=,comm=']);
    return childrenOf(stdout, pid);
  }

  /** Whether a bound or a stalled read took this instance away. */
  get abandoned(): boolean {
    return this.wasAbandoned;
  }

  /**
   * Takes the mount away without an orderly quit.
   *
   * A kernel call on a mount carries no timeout, so a mount that stopped
   * answering holds its caller — and with it one of the few filesystem threads
   * Node has. Removing the mount is what returns those calls, so a scenario
   * that ran out of time does this before it does anything else.
   */
  async abandon(): Promise<void> {
    this.wasAbandoned = true;
    this.shell.child.kill('SIGKILL');
    await forceUnmount(this.mountRoot);
  }

  /**
   * Unmounts the vault the way a member at a terminal does, and leaves the
   * shell running. Throws where the host has no such tool, or the tool fails.
   */
  async unmountExternally(): Promise<void> {
    const tool = unmountTool(this.mountRoot);
    if (!tool) throw new Error(`${process.platform} has no tool to unmount from outside the app`);
    await run(tool.command, tool.args, { timeout: UNMOUNT_WITHIN_MS });
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

  // Windows resolves the local data directory as `%USERPROFILE%\AppData\Local`
  // and reports none until that directory exists, so the home is given the
  // shape of a profile before the shell reads it.
  const profile = process.platform === 'win32' ? join(home, 'AppData', 'Local') : home;
  await mkdir(profile, { recursive: true });
  await mkdir(logDir, { recursive: true });
  // `prepare()` refuses a mount point that already holds anything, and no
  // status reports a path yet, so the sweep uses the shell's own default.
  await rm(join(home, DEFAULT_MOUNT_NAME), { recursive: true, force: true });

  const controlFile = join(home, 'control');
  const dataDir = join(home, 'data');
  await rm(controlFile, { force: true });

  const logPath = join(logDir, `${name}.log`);
  const log = createWriteStream(logPath);
  const child = spawn(binary, ['--dev-key-stdin', '--control-file', controlFile], {
    // The OS resolver can ignore the per-instance home (the Windows known
    // folders, a runner's `XDG_DATA_HOME`), so the data directory is named.
    env: { ...process.env, HOME: home, USERPROFILE: home, [DATA_DIR_ENV]: dataDir },
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

  // A start that fails owns the child: no `Instance` exists yet, so nothing
  // else can stop it, and its open pipes would hold the whole run alive.
  try {
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

    await poll(
      async () => {
        await refuseIfDead(shell, name);
        return announcedDataDir(await readFile(logPath, 'utf8').catch(() => ''));
      },
      (announced) => announced === dataDir,
      {
        what: `${name} to announce its data directory as ${dataDir}`,
        timeoutMs: budget.controlFileMs,
        intervalMs: budget.intervalMs,
      }
    );

    const opened = await poll(
      async (): Promise<MountStatus> => {
        await refuseIfDead(shell, name);
        const status = await statusOrPending(endpoint, budget.refreshMs);
        // No session yet is the cold start, not a failure: keep waiting.
        if (!status) return { state: 'opening' };
        if (status.mount.state === 'refused') {
          throw new Error(`${name} refused to mount: ${status.mount.reason}`);
        }
        return status.mount;
      },
      (mount): mount is { state: 'mounted'; path: string } => mount.state === 'mounted',
      {
        what: `${name}: the session to start and the mount to open`,
        timeoutMs: budget.mountMs,
        intervalMs: budget.intervalMs,
      }
    );

    return new Instance(name, opened.path, shell, endpoint, budget);
  } catch (error) {
    if (!shell.exit) child.kill('SIGKILL');
    await forceUnmount(join(home, DEFAULT_MOUNT_NAME));
    throw error;
  }
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

/** One row of the process table. */
export interface ChildProcessRow {
  pid: number;
  /** Ended, and not yet reaped by its parent. */
  zombie: boolean;
  command: string;
}

/** The rows of `ps -o pid=,ppid=,stat=,comm=` output whose parent is `parent`. */
export function childrenOf(psOutput: string, parent: number): ChildProcessRow[] {
  const rows: ChildProcessRow[] = [];
  for (const line of psOutput.split('\n')) {
    const [pid, ppid, stat, ...command] = line.trim().split(/\s+/);
    if (stat === undefined || Number(ppid) !== parent) continue;
    rows.push({ pid: Number(pid), zombie: stat.startsWith('Z'), command: command.join(' ') });
  }
  return rows;
}

/** The tool a member unmounts with from outside the app, where one exists. */
function unmountTool(mountRoot: string): { command: string; args: string[] } | null {
  return process.platform === 'darwin'
    ? { command: 'diskutil', args: ['unmount', 'force', mountRoot] }
    : process.platform === 'linux'
      ? { command: 'fusermount3', args: ['-u', mountRoot] }
      : null;
}

/** Best effort: the kernel can keep the mount after a killed shell. */
async function forceUnmount(mountRoot: string): Promise<void> {
  const tool = unmountTool(mountRoot);
  if (!tool) return;
  try {
    await run(tool.command, tool.args, { timeout: UNMOUNT_WITHIN_MS });
  } catch {
    // The mount was already gone, the tool is absent on this host, or it ran
    // out of its own time.
  }
}
