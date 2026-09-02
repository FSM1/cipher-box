/**
 * Every wire detail of the desktop control endpoint, in one module.
 *
 * The shell binds a loopback listener under the `e2e-hook` build and writes
 * `<port> <token>` to the control file. One request per connection: the suite
 * sends `<token> <verb>` and reads one JSON line back.
 */

import { readFile } from 'node:fs/promises';
import { createConnection } from 'node:net';

export type ControlVerb = 'status' | 'refresh' | 'quit';

export type Staleness = 'fresh' | 'reconciling' | 'stale' | 'offline';

export interface VaultWarning {
  kind: string;
  detail: string | null;
}

export type MountStatus =
  | { state: 'opening' }
  | { state: 'mounted'; path: string }
  | { state: 'refused'; reason: string };

export interface VaultStatus {
  items: number;
  staleness: Staleness;
  deadLetters: number;
  provisioned: boolean;
  warnings: VaultWarning[];
  mount: MountStatus;
}

export type ControlResponse = { ok: true; status?: VaultStatus } | { ok: false; error: string };

export interface ControlEndpoint {
  port: number;
  token: string;
}

/** The endpoint spoke, but the answer was not one this suite understands. */
export class ControlProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ControlProtocolError';
  }
}

const TOKEN_PATTERN = /^[0-9a-f]{64}$/;
const MAX_PORT = 65535;
const MAX_RESPONSE_BYTES = 64 * 1024;
const NEWLINE = 0x0a;

/**
 * Reads the one line the shell wrote.
 *
 * The token never reaches a message: an error names the field, never its
 * value.
 */
export function parseControlFile(text: string): ControlEndpoint {
  const lines = text.split('\n').filter((line) => line.length > 0);
  if (lines.length === 0) throw new ControlProtocolError('the control file is empty');
  if (lines.length > 1) {
    throw new ControlProtocolError(`the control file holds ${lines.length} lines, not one`);
  }

  const fields = lines[0].split(' ');
  if (fields.length !== 2) {
    throw new ControlProtocolError(
      `the control file line holds ${fields.length} fields, not a port and a token`
    );
  }

  const [rawPort, token] = fields;
  if (!/^[0-9]+$/.test(rawPort)) {
    throw new ControlProtocolError('the control file port is not a number');
  }
  const port = Number(rawPort);
  if (port < 1 || port > MAX_PORT) {
    throw new ControlProtocolError(`the control file port ${port} is outside 1..${MAX_PORT}`);
  }
  if (!TOKEN_PATTERN.test(token)) {
    throw new ControlProtocolError('the control file token is not 64 lowercase hex characters');
  }
  return { port, token };
}

/** The exact bytes of one request. */
export function formatRequest(endpoint: ControlEndpoint, verb: ControlVerb): string {
  return `${endpoint.token} ${verb}\n`;
}

export function parseResponse(line: string): ControlResponse {
  let parsed: unknown;
  try {
    parsed = JSON.parse(line);
  } catch {
    throw new ControlProtocolError(`the control endpoint answered non-JSON: ${excerpt(line)}`);
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new ControlProtocolError(`the control answer is not an object: ${excerpt(line)}`);
  }

  const body = parsed as Record<string, unknown>;
  if (body.ok === true) {
    const status = body.status;
    return status === undefined ? { ok: true } : { ok: true, status: vaultStatus(status) };
  }
  if (body.ok === false) {
    const error = typeof body.error === 'string' ? body.error : 'no reason given';
    return { ok: false, error };
  }
  throw new ControlProtocolError(`the control answer carries no ok field: ${excerpt(line)}`);
}

const STALENESS: readonly string[] = ['fresh', 'reconciling', 'stale', 'offline'];

/**
 * The status a well-formed answer carries.
 *
 * Every field is checked here, so a shell that answers a shape this suite does
 * not know fails with a named protocol error rather than with a `TypeError`
 * from the first reader that walks into an absent field.
 */
function vaultStatus(value: unknown): VaultStatus {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new ControlProtocolError('the control status is not an object');
  }
  const status = value as Record<string, unknown>;
  for (const name of ['items', 'deadLetters'] as const) {
    if (typeof status[name] !== 'number') {
      throw new ControlProtocolError(`the control status field ${name} is not a number`);
    }
  }
  if (typeof status.provisioned !== 'boolean') {
    throw new ControlProtocolError('the control status field provisioned is not a boolean');
  }
  if (typeof status.staleness !== 'string' || !STALENESS.includes(status.staleness)) {
    throw new ControlProtocolError('the control status carries no staleness this suite knows');
  }
  if (!Array.isArray(status.warnings)) {
    throw new ControlProtocolError('the control status field warnings is not an array');
  }
  mountStatus(status.mount);
  return status as unknown as VaultStatus;
}

/** The mount state a well-formed status carries, with the field its state needs. */
function mountStatus(value: unknown): void {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new ControlProtocolError('the control status field mount is not an object');
  }
  const mount = value as Record<string, unknown>;
  if (mount.state === 'opening') return;
  if (mount.state === 'mounted' && typeof mount.path === 'string') return;
  if (mount.state === 'refused' && typeof mount.reason === 'string') return;
  throw new ControlProtocolError('the control status carries no mount state this suite knows');
}

/** Reads the control file, or returns null while the shell has not written it. */
export async function readEndpoint(path: string): Promise<ControlEndpoint | null> {
  let text: string;
  try {
    text = await readFile(path, 'utf8');
  } catch {
    return null;
  }
  // A line without its terminator is a file still on its way, not a bad one.
  if (!text.includes('\n')) return null;
  return parseControlFile(text);
}

/** Sends one verb and returns the endpoint's own answer, refusal included. */
async function send(
  endpoint: ControlEndpoint,
  verb: ControlVerb,
  timeoutMs: number
): Promise<ControlResponse> {
  const line = await exchange(endpoint, formatRequest(endpoint, verb), timeoutMs);
  return parseResponse(line);
}

/** The endpoint answered and refused the verb. Its own class, because a shell
 * that is still starting refuses `status` and that is a state to wait out. */
export class ControlRefusal extends Error {
  constructor(
    readonly verb: ControlVerb,
    readonly refusal: string
  ) {
    super(`the control endpoint refused ${verb}: ${refusal}`);
    this.name = 'ControlRefusal';
  }
}

export async function sendOrThrow(
  endpoint: ControlEndpoint,
  verb: ControlVerb,
  timeoutMs: number
): Promise<ControlResponse & { ok: true }> {
  const answer = await send(endpoint, verb, timeoutMs);
  if (!answer.ok) throw new ControlRefusal(verb, answer.error);
  return answer;
}

export async function status(endpoint: ControlEndpoint, timeoutMs: number): Promise<VaultStatus> {
  const answer = await sendOrThrow(endpoint, 'status', timeoutMs);
  if (!answer.status) {
    throw new ControlProtocolError('the control endpoint accepted status but sent no status');
  }
  return answer.status;
}

export async function refresh(endpoint: ControlEndpoint, timeoutMs: number): Promise<void> {
  await sendOrThrow(endpoint, 'refresh', timeoutMs);
}

export async function quit(endpoint: ControlEndpoint, timeoutMs: number): Promise<void> {
  await sendOrThrow(endpoint, 'quit', timeoutMs);
}

function exchange(endpoint: ControlEndpoint, request: string, timeoutMs: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = createConnection({ host: '127.0.0.1', port: endpoint.port });
    // The bytes are framed before they are decoded: a mount path or a warning
    // detail can carry a character whose bytes cross two chunks, and a decode
    // per chunk turns that character into U+FFFD.
    let raw = Buffer.alloc(0);
    let settled = false;

    const finish = (error: Error | null, line?: string) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      if (error) reject(error);
      else resolve(line as string);
    };

    socket.setTimeout(timeoutMs, () =>
      finish(new ControlProtocolError(`the control endpoint did not answer within ${timeoutMs}ms`))
    );
    socket.on('error', (error) =>
      finish(new ControlProtocolError(`the control endpoint is unreachable: ${error.message}`))
    );
    socket.on('connect', () => socket.write(request));
    socket.on('data', (chunk: Buffer) => {
      raw = Buffer.concat([raw, chunk]);
      const newline = raw.indexOf(NEWLINE);
      if (newline >= 0 && newline <= MAX_RESPONSE_BYTES) {
        finish(null, raw.subarray(0, newline).toString('utf8'));
        return;
      }
      if (raw.length > MAX_RESPONSE_BYTES) {
        finish(new ControlProtocolError('the control answer exceeded the byte ceiling'));
      }
    });
    socket.on('end', () => {
      if (raw.length > 0) finish(null, raw.toString('utf8'));
      else finish(new ControlProtocolError('the control endpoint closed without an answer'));
    });
  });
}

function excerpt(line: string): string {
  const trimmed = line.trim();
  return trimmed.length > 120 ? `${trimmed.slice(0, 120)}…` : trimmed;
}
