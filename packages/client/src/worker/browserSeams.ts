/**
 * Constructs the eight browser seams for one engine instance, inside the worker
 * realm (blueprint/web-client.md "Browser seams"). The seam bag's property names
 * are the constructor contract the WASM `EngineHandle` reads.
 */

import {
  ApiMailbox,
  FetchHttp,
  FetchRecordTransport,
  IdbFloorStore,
  IdbSnapshotCache,
  NoopCredentialStore,
  OpfsStagingStore,
  WorkerScheduler,
} from '../seams/index.js';

export interface BrowserSeamsConfig {
  /** Delegated-routing endpoint set for `RecordTransport` (someguy + public). */
  recordEndpoints: string[];
  /** Absolute base URL of the API; `Mailbox` appends its own routes. */
  apiBaseUrl: string;
  /** Prefix for the IndexedDB/OPFS store names (namespaces per origin/test). */
  dbPrefix?: string;
}

/** Store names are built from the account id, so it is bounded and path-free. */
const ACCOUNT_ID = /^[0-9a-z][0-9a-z-]{0,127}$/;

/** The seam bag the WASM `EngineHandle` constructor reads. */
export interface BrowserSeams {
  floorStore: IdbFloorStore;
  recordTransport: FetchRecordTransport;
  http: FetchHttp;
  mailbox: ApiMailbox;
  scheduler: WorkerScheduler;
  stagingStore: OpfsStagingStore;
  snapshotCache: IdbSnapshotCache;
  credentialStore: NoopCredentialStore;
}

/**
 * `accountId` namespaces every durable store, so two accounts signed in on one
 * browser profile cannot share an epoch floor keyed by the constant root scope
 * id — which would refuse the lower-epoch account's cold start as a rollback,
 * with no way back (blueprint/engine.md "Floor law").
 */
export function makeBrowserSeams(config: BrowserSeamsConfig, accountId: string): BrowserSeams {
  if (!ACCOUNT_ID.test(accountId)) throw new Error('account id is not a store namespace');
  const prefix = `${config.dbPrefix ?? 'cipherbox'}-${accountId}`;
  const http = new FetchHttp();
  return {
    floorStore: new IdbFloorStore(`${prefix}-floors`),
    recordTransport: new FetchRecordTransport(config.recordEndpoints),
    http,
    mailbox: new ApiMailbox(http, config.apiBaseUrl),
    scheduler: new WorkerScheduler(),
    stagingStore: new OpfsStagingStore(`${prefix}-staging`),
    snapshotCache: new IdbSnapshotCache(`${prefix}-snapshot-cache`),
    credentialStore: new NoopCredentialStore(),
  };
}
