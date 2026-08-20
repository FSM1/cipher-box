/**
 * The browser seam implementations — the web side of the engine's host seam
 * traits (blueprint/web-client.md "Browser seams"), all pure byte I/O over
 * IndexedDB, OPFS, and `fetch`. No crypto, no codec: every trust decision
 * already happened below the facade in the Rust engine.
 */

export { fromHex, toHex } from './bytes.js';
export { IdbFloorStore } from './floorStore.js';
export { IdbSnapshotCache } from './snapshotCache.js';
export {
  OpfsStagingStore,
  STAGED_DIR_SUFFIX,
  STAGING_DB_VERSION,
  STAGING_OPS_STORE,
} from './stagingStore.js';
export { NoopCredentialStore } from './credentialStore.js';
export { WorkerScheduler } from './scheduler.js';
export { FetchRecordTransport } from './recordTransport.js';
export { FetchHttp } from './http.js';
export { ApiMailbox } from './mailbox.js';
export type {
  FloorStoreSeam,
  SnapshotCacheSeam,
  StagingStoreSeam,
  CredentialStoreSeam,
  SchedulerSeam,
  RecordTransportSeam,
  CappedRecordResult,
  TooLargeResult,
  HttpSeam,
  HttpRequestData,
  HttpResponseData,
  CappedHttpResult,
  MailboxSeam,
  MailboxItemData,
} from './types.js';
