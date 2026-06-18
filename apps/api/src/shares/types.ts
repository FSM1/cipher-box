/**
 * Shared key type definitions for share-related DTOs and entities.
 *
 * Arrays are the source of truth — used in @IsIn() validators and to derive TypeScript types.
 */

/**
 * Valid key types for child keys during share/invite creation.
 *
 * Includes `folder-ipns` so a read-write folder share can grant the recipient
 * write access to owner-created descendant subfolders (the IPNS signing key),
 * mirroring `file-ipns` for files. Without it, descendants were read-only even
 * on a write share, so the recipient could not move/write into them.
 */
export const CHILD_KEY_TYPES = ['file', 'folder', 'file-ipns', 'folder-ipns'] as const;
export type ChildKeyType = (typeof CHILD_KEY_TYPES)[number];

/** Valid key types for share_keys — identical to the child key types. */
export const SHARE_KEY_TYPES = CHILD_KEY_TYPES;
export type ShareKeyType = ChildKeyType;
