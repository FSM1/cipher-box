/**
 * Type declarations for @phala/dstack-sdk
 *
 * The dstack SDK is only available inside Phala Cloud CVM at runtime.
 * These declarations allow TypeScript compilation in simulator mode
 * where the SDK is not installed.
 */

declare module '@phala/dstack-sdk' {
  export class DstackClient {
    constructor();
    getKey(
      path: string,
      subject: string
    ): Promise<{
      asUint8Array(): Uint8Array;
    }>;
    getQuote(reportData: Uint8Array): Promise<unknown>;
    info(): Promise<unknown>;
  }
}
