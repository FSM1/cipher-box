// API client configuration
export {
  customInstance,
  createAxiosInstance,
  setApiClientConfig,
  getApiClientConfig,
} from './instance';
export type {
  ApiClientConfig,
  ErrorType,
  BodyType,
  AxiosInstance,
  AxiosProgressEvent,
  CancelToken,
} from './instance';
export { axios } from './instance';

// Generated API functions (re-export all)
export * from './generated/auth/auth';
export * from './generated/device-approval/device-approval';
export * from './generated/health/health';
export * from './generated/identity/identity';
export * from './generated/invites/invites';
export * from './generated/ipfs/ipfs';
export * from './generated/ipns/ipns';
export * from './generated/root/root';
export * from './generated/share-invites/share-invites';
export * from './generated/shares/shares';
export * from './generated/tee/tee';
export * from './generated/vault/vault';

// Generated model types
export * from './models';
