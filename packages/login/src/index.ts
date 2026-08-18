/**
 * The host-agnostic login package (ADR 0008 D3). It owns the sequencing and the
 * API's identity surface; the host owns credential collection, the Core Kit
 * instance, and the facade this starts.
 */

export {
  collectedMethods,
  type CollectedMaterial,
  type CredentialCollector,
  type EmailAnswer,
  type WalletProof,
} from './collector';
export { createLoginFlow, type LoginFlow, type LoginHost } from './flow';
export {
  createIdentityExchange,
  isIdentityMethod,
  type IdentityCredential,
  type IdentityExchange,
  type IdentityMethod,
} from './identity';
export {
  exportLoginSecret,
  handOffLoginSecret,
  type LoginFacade,
  type LoginSecretExporter,
} from './secret';
export {
  RecoveryRequiredError,
  type AccountRecord,
  type CoreKitSession,
  type LoginProgress,
  type SecretRearm,
} from './session';
