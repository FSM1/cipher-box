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

export function makeBrowserSeams(config: BrowserSeamsConfig): BrowserSeams {
  const prefix = config.dbPrefix ?? 'cipherbox';
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
