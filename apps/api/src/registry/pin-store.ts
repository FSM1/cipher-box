import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

/**
 * The physical-unpin seam (blueprint/api.md: "physical unpin fires at global
 * refcount zero" — v1's `guardedUnpin` survives). The registry owns the
 * refcount DECISION; this port owns the side effect of releasing bytes from
 * the hosted pin store.
 *
 * It is a best-effort liveness optimization, not a correctness dependency:
 * the per-account row bookkeeping is the source of truth, so a failed or
 * unconfigured unpin never fails a retire. The pinned CID simply lingers and
 * decays from the pin store's own GC — never re-registered, so union liveness
 * still reports it gone.
 */
@Injectable()
export abstract class PinStore {
  abstract unpin(cid: string): Promise<void>;
}

/**
 * Default hosted implementation: releases a CID from CipherBox Kubo when
 * `KUBO_API_URL` is configured. Absent that config (unit tests, BYO-only
 * deployments), it no-ops — the hosted byte path is wired by the content-plane
 * slice; this slice ships the refcount decision that drives it.
 */
@Injectable()
export class KuboPinStore extends PinStore {
  private readonly logger = new Logger(PinStore.name);
  private readonly apiUrl: string | undefined;

  constructor(configService: ConfigService) {
    super();
    const raw = configService.get<string>('KUBO_API_URL');
    this.apiUrl = raw && raw.trim() ? raw.replace(/\/+$/, '') : undefined;
  }

  async unpin(cid: string): Promise<void> {
    if (!this.apiUrl) {
      return;
    }
    try {
      await fetch(`${this.apiUrl}/api/v0/pin/rm?arg=${encodeURIComponent(cid)}&recursive=true`, {
        method: 'POST',
      });
    } catch (error) {
      // Best-effort: bookkeeping already dropped the row, so a Kubo hiccup
      // must not fail the caller's retire. Log and move on.
      this.logger.warn(`pin/rm failed for ${cid}: ${String(error)}`);
    }
  }
}
