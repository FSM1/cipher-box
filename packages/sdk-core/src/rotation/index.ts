// Rotation module barrel — export-only, no logic (coverage exclusion intentional: src/**/index.ts)

export {
  rotateReadFromNode,
  rotateOne,
  mintFileKeyOnRotate,
  reMintGrantsRootedAt,
  mergeConcurrentChildren,
  verifySubtreeClean,
  rotateWriteFromNode,
  RootKeyStaleError,
  DirtyNodeUnrecoverableError,
  type RotationJobRecord,
  type RotationStatus,
  type RotationParams,
  type RotateReadResult,
  type RotatedNodeKey,
  type WriteRevocationCallbacks,
  type GrantRemintCallbacks,
  type KeyCheckpointCallbacks,
  type DirtyFrontierItem,
} from './engine';

export {
  hasCoveringGrant,
  maybeRotateOnScopeExit,
  type CoverageParams,
  type ScopeExitResult,
  type ScopeExitDeps,
} from './scope';

export { mergeRotatedChildren } from './merge';
