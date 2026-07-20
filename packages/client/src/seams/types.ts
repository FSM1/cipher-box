/**
 * The browser seam interfaces.
 *
 * These are the JS-side shape of the engine's host seam traits
 * (`crates/engine/src/seams`, blueprint/engine.md). The engine — compiled to
 * WASM — drives them through the conformance bridge in `crates/wasm`: every
 * `Uint8Array` argument is an opaque engine-chosen byte string the seam only
 * addresses, never interprets, and no seam does any crypto or codec of its own
 * (blueprint/web-client.md doctrine).
 *
 * Numeric seam values (floors, sequence numbers, op ids, byte totals) cross as
 * JS `number`. The production facade carries `u64`s as `bigint`
 * (blueprint/web-client.md "Boundary hygiene"); the conformance bridge narrows
 * them to `f64` for the test path only, whose value domain is far below
 * `Number.MAX_SAFE_INTEGER`.
 */

/**
 * Durable monotonic-max per-scope epoch floors and per-name sequence floors.
 * The floor law lives in the engine; this seam only stores (fail-closed
 * regression is a property of `raise*` never lowering a floor).
 */
export interface FloorStoreSeam {
  epochFloor(scopeId: Uint8Array): Promise<number | null>;
  raiseEpochFloor(scopeId: Uint8Array, epoch: number): Promise<number>;
  sequenceFloor(ipnsName: Uint8Array): Promise<number | null>;
  raiseSequenceFloor(ipnsName: Uint8Array, sequence: number): Promise<number>;
}

/** Durable last-known-good record/metadata cache, ciphertext-only at rest. */
export interface SnapshotCacheSeam {
  put(cacheKey: Uint8Array, ciphertext: Uint8Array): Promise<void>;
  get(cacheKey: Uint8Array): Promise<Uint8Array | null>;
  remove(cacheKey: Uint8Array): Promise<void>;
  clear(): Promise<void>;
}

/** Durable op queue (FIFO, strictly increasing never-reused ids) plus staged bytes. */
export interface StagingStoreSeam {
  enqueueOp(op: Uint8Array): Promise<number>;
  queuedOps(): Promise<Array<[number, Uint8Array]>>;
  removeOp(opId: number): Promise<void>;
  putStagedBytes(stagingKey: Uint8Array, bytes: Uint8Array): Promise<void>;
  stagedBytes(stagingKey: Uint8Array): Promise<Uint8Array | null>;
  removeStagedBytes(stagingKey: Uint8Array): Promise<void>;
  stagedKeys(): Promise<Uint8Array[]>;
  stagedBytesTotal(): Promise<number>;
}

/** Refresh-token persistence. Web is a no-op (the HTTP-only cookie rides `Http`). */
export interface CredentialStoreSeam {
  storeRefreshToken(refreshToken: Uint8Array): Promise<void>;
  loadRefreshToken(): Promise<Uint8Array | null>;
  clearRefreshToken(): Promise<void>;
}

/** Wall clock and delays. Background task execution (`spawn`) is engine-side. */
export interface SchedulerSeam {
  now(): number;
  sleep(durationMs: number): Promise<void>;
}

/** Dumb `/routing/v1` byte mover: GET/PUT of opaque signed record bytes. */
export interface RecordTransportSeam {
  endpoints(): string[];
  getRecord(endpoint: string, routingKey: string): Promise<Uint8Array | null>;
  putRecord(endpoint: string, routingKey: string, record: Uint8Array): Promise<void>;
}

/** One HTTP request fully described by the engine. */
export interface HttpRequestData {
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD';
  url: string;
  headers: Array<[string, string]>;
  body: Uint8Array | null;
}

/** One HTTP response, returned verbatim to the engine. */
export interface HttpResponseData {
  status: number;
  headers: Array<[string, string]>;
  body: Uint8Array;
}

/**
 * Plain HTTP for the API client, trustless gateway, and BYO providers. A pure
 * byte mover: non-2xx statuses are responses, not errors; only transport-level
 * failure rejects.
 */
export interface HttpSeam {
  send(request: HttpRequestData): Promise<HttpResponseData>;
}
