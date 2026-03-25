import type { PinningProvider, PinResult, PinStatus } from './types';

export type DualPinResult = PinResult & {
  secondarySuccess: boolean;
  secondaryError?: string;
};

/**
 * Orchestrates pinning to both a primary and secondary provider.
 *
 * Primary pin MUST succeed. Secondary pin is best-effort:
 * - If secondary fails, operation still succeeds with a warning.
 * - Caller receives secondarySuccess flag to show non-blocking toast.
 */
export class DualPinProvider implements PinningProvider {
  constructor(
    private readonly primary: PinningProvider,
    private readonly secondary: PinningProvider
  ) {}

  async pin(data: Uint8Array, name?: string): Promise<DualPinResult> {
    // Primary MUST succeed
    const primaryResult = await this.primary.pin(data, name);

    // Secondary is best-effort
    let secondarySuccess = false;
    let secondaryError: string | undefined;
    try {
      await this.secondary.pin(data, name);
      secondarySuccess = true;
    } catch (err) {
      secondaryError = err instanceof Error ? err.message : String(err);
    }

    return {
      ...primaryResult,
      secondarySuccess,
      secondaryError,
    };
  }

  async unpin(cid: string): Promise<void> {
    // Unpin from both, primary must succeed
    await this.primary.unpin(cid);
    // Secondary unpin is best-effort
    try {
      await this.secondary.unpin(cid);
    } catch {
      // Ignore secondary unpin failure
    }
  }

  async status(cid: string): Promise<PinStatus> {
    // Status checks primary only
    return this.primary.status(cid);
  }

  async get(cid: string): Promise<Uint8Array> {
    // Retrieve from primary
    return this.primary.get(cid);
  }
}
