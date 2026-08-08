/**
 * Ambient declarations for the OPFS synchronous access handle API used by
 * {@link OpfsStagingStore} in the worker realm. These are stable in Chromium
 * but not yet part of this TypeScript version's bundled `lib.dom`, so they are
 * declared here rather than pulled from an external `@types` package.
 */
export {};

declare global {
  interface FileSystemSyncAccessHandle {
    read(buffer: ArrayBufferView, options?: { at?: number }): number;
    write(buffer: ArrayBufferView, options?: { at?: number }): number;
    truncate(newSize: number): void;
    getSize(): number;
    flush(): void;
    close(): void;
  }

  interface FileSystemFileHandle {
    createSyncAccessHandle(): Promise<FileSystemSyncAccessHandle>;
    /** Renames within the directory, replacing any entry already at `name`. */
    move(name: string): Promise<void>;
  }
}
