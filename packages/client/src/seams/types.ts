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
 *
 * Per-key only, by design: there is deliberately no batch/commit method here.
 * A cross-key floor advance rides the engine seam's ordered fail-safe fallback
 * (`FloorStore::commit_floors` default), which commits the revocation floor
 * first and re-converges idempotently on retry.
 */
export interface FloorStoreSeam {
  epochFloor(scopeId: Uint8Array): Promise<number | null>;
  raiseEpochFloor(scopeId: Uint8Array, epoch: number): Promise<number>;
  sequenceFloor(ipnsName: Uint8Array): Promise<number | null>;
  raiseSequenceFloor(ipnsName: Uint8Array, sequence: number): Promise<number>;
  /** Drops every floor in both namespaces ("forget this device"). */
  clear(): Promise<void>;
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
  /**
   * Drops every queued op and every staged byte ("forget this device"). The id
   * progression is not reset — ids stay strictly increasing and unreused.
   *
   * The queue goes before the staged bytes: interrupted the other way round,
   * the store is left holding ops that name bytes already gone, while this
   * order can only orphan bytes that orphan GC reclaims. Both legs run even
   * when one refuses, and the first refusal is what the caller sees.
   */
  clear(): Promise<void>;
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

/**
 * A body refused for exceeding its inclusive byte cap. Fail-closed: no bytes
 * cross, and the counts are diagnostic only (see `cappedBody.ts`).
 */
export interface TooLargeResult {
  kind: 'tooLarge';
  observed: number;
  limit: number;
}

/** A capped record GET: the stored bytes, `null` for absence, or over-cap. */
export type CappedRecordResult = { kind: 'record'; record: Uint8Array | null } | TooLargeResult;

/**
 * Dumb `/routing/v1` byte mover: GET/PUT of opaque signed record bytes.
 *
 * The endpoint set includes untrusted public endpoints, so `getRecord` bounds
 * the read at `maxBytes` as the body arrives (see `cappedBody.ts`).
 */
export interface RecordTransportSeam {
  endpoints(): string[];
  getRecord(endpoint: string, routingKey: string, maxBytes: number): Promise<CappedRecordResult>;
  putRecord(endpoint: string, routingKey: string, record: Uint8Array): Promise<void>;
}

/** One HTTP request fully described by the engine. */
export interface HttpRequestData {
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD';
  url: string;
  headers: Array<[string, string]>;
  body: Uint8Array | null;
  /**
   * Ambient-credential scope. Absent means `'omit'`: only the API origin is
   * asked for the HTTP-only refresh cookie, so a gateway gets no authority it
   * could use to correlate the per-leaf fetches.
   */
  credentials?: 'include' | 'omit';
  /** Whole-request deadline in ms, per request class; absent leaves it unbounded. */
  timeoutMs?: number | null;
}

/** One HTTP response, returned verbatim to the engine. */
export interface HttpResponseData {
  status: number;
  headers: Array<[string, string]>;
  body: Uint8Array;
}

export type CappedHttpResult = ({ kind: 'response' } & HttpResponseData) | TooLargeResult;

/**
 * Plain HTTP for the API client, trustless gateway, and BYO providers. A pure
 * byte mover: non-2xx statuses are responses, not errors; only transport-level
 * failure rejects.
 *
 * `sendCapped` bounds peak memory while the body is still arriving; `maxBytes`
 * is inclusive, so a body of exactly `maxBytes` is admitted.
 */
export interface HttpSeam {
  send(request: HttpRequestData): Promise<HttpResponseData>;
  sendCapped(request: HttpRequestData, maxBytes: number): Promise<CappedHttpResult>;
}

/** One pending mailbox item; `sealedPayload` is opaque (the engine unseals it). */
export interface MailboxItemData {
  itemId: string;
  sealedPayload: Uint8Array;
}

/**
 * Sealed-blob discovery transport (share pointers, invite claims). An
 * integrity-untrusted byte mover: nothing on it is load-bearing for safety, and
 * it does no crypto or codec — the engine seals, unseals, and authenticates.
 */
export interface MailboxSeam {
  post(
    recipientPublicKey: Uint8Array,
    sealedPayload: Uint8Array,
    idempotencyKey: string
  ): Promise<void>;
  poll(): Promise<MailboxItemData[]>;
  ack(itemId: string): Promise<void>;
}
