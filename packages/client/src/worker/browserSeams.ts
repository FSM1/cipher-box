/**
 * Constructs the seven browser seams for one engine instance, inside the worker
 * realm (blueprint/web-client.md "Browser seams"). The seam bag's property names
 * are the constructor contract the WASM `EngineHandle` reads.
 */

import {
  ACCOUNT_ID,
  DEFAULT_DB_PREFIX,
  FLOORS,
  SNAPSHOT_CACHE,
  STAGING,
  type AccountStoreNaming,
} from '../accountStores.js';
import {
  FetchHttp,
  FetchRecordTransport,
  IdbFloorStore,
  IdbSnapshotCache,
  NoopCredentialStore,
  OpfsStagingStore,
  WorkerScheduler,
} from '../seams/index.js';

export interface BrowserSeamsConfig extends AccountStoreNaming {
  /** Delegated-routing endpoint set for `RecordTransport` (someguy + public). */
  recordEndpoints: string[];
}

/** The seam bag the WASM `EngineHandle` constructor reads. */
export interface BrowserSeams {
  floorStore: IdbFloorStore;
  recordTransport: FetchRecordTransport;
  http: FetchHttp;
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
  const prefix = `${config.dbPrefix ?? DEFAULT_DB_PREFIX}-${accountId}`;
  return {
    floorStore: new IdbFloorStore(`${prefix}-${FLOORS}`),
    recordTransport: new FetchRecordTransport(config.recordEndpoints),
    http: new FetchHttp(),
    scheduler: new WorkerScheduler(),
    stagingStore: new OpfsStagingStore(`${prefix}-${STAGING}`),
    snapshotCache: new IdbSnapshotCache(`${prefix}-${SNAPSHOT_CACHE}`),
    credentialStore: new NoopCredentialStore(),
  };
}
