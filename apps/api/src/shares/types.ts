/**
 * Shared key type definitions for share-related DTOs and entities.
 *
 * Arrays are the source of truth — used in @IsIn() validators and to derive TypeScript types.
 */

/** Valid key types for child keys during share/invite creation. */
export const CHILD_KEY_TYPES = ['file', 'folder', 'file-ipns'] as const;
export type ChildKeyType = (typeof CHILD_KEY_TYPES)[number];

/** Valid key types for share_keys (includes folder-ipns for subfolder write access). */
export const SHARE_KEY_TYPES = [...CHILD_KEY_TYPES, 'folder-ipns'] as const;
export type ShareKeyType = (typeof SHARE_KEY_TYPES)[number];
