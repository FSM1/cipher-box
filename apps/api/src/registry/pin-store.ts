import { Injectable, Logger, ServiceUnavailableException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { contentCidCodec } from '../common/content-cid';

/**
 * The hosted pin-store port (blueprint/api.md, Content plane + "physical unpin
 * fires at global refcount zero" — v1's `guardedUnpin` survives). It owns every
 * side effect against CipherBox Kubo: durably pinning bytes under the address
 * the caller declared for them, and releasing bytes at refcount zero. The
 * registry and content services own the row DECISIONS; this port owns the byte
 * effects.
 *
 * `unpin` is a best-effort liveness optimization, not a correctness dependency:
 * the per-account row bookkeeping is the source of truth, so a failed or
 * unconfigured unpin never fails a retire — the CID lingers and decays from the
 * pin store's own GC. It returns whether the CID was physically released (`true`)
 * so callers report a truthful unpin count; a no-op or swallowed failure returns
 * `false` (never throws). `pin` is the ingress byte path; a consumer that only
 * retires (the registry) never calls it, so the base rejects rather than forcing
 * every unpin-only fake to stub the byte method.
 */
@Injectable()
export abstract class PinStore {
  abstract unpin(cid: string): Promise<boolean>;

  /**
   * Durably pin `bytes` under the caller-declared content address `cid`,
   * rejecting with [`PinCidMismatchError`] when the store addresses those bytes
   * differently — the check that binds a declared CID to the bytes behind it.
   */
  pin(_cid: string, _bytes: Uint8Array): Promise<void> {
    throw new ServiceUnavailableException('Hosted pin store does not support pinning');
  }
}

/**
 * The declared CID does not address the uploaded bytes. A caller fault, not a
 * store outage: the ingress path answers 400 so the client fails fast instead
 * of retrying an upload that can never succeed.
 */
export class PinCidMismatchError extends Error {
  constructor(
    readonly declared: string,
    readonly actual: string
  ) {
    super(`Declared CID ${declared} does not address the uploaded bytes (${actual})`);
    this.name = 'PinCidMismatchError';
  }
}

/** One Kubo `block/put` result; only `Key` (the block's address) is consumed. */
interface KuboBlockPutResult {
  Key: string;
}

/**
 * Default hosted implementation over the Kubo RPC API (`KUBO_API_URL`). `unpin`
 * no-ops when Kubo is unconfigured (unit tests, BYO-only deployments); the byte
 * path fails closed instead, since an upload with no pin store cannot be
 * durable.
 *
 * `pin` writes the block under the declared CID's own multicodec and BLAKE3-256
 * multihash, so Kubo addresses it exactly as the engine does, then pins it
 * **direct** (`recursive=false`). Direct is the correct shape for this plane:
 * every block is uploaded and registered individually, and a recursive pin would
 * make repo GC walk sealed bytes it cannot interpret.
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

  override async pin(cid: string, bytes: Uint8Array): Promise<void> {
    const codec = contentCidCodec(cid);
    if (!codec) {
      throw new PinCidMismatchError(cid, 'not a content-plane CID');
    }
    // Written unpinned first: a block whose address disagrees is never pinned,
    // so a wrong declaration leaves nothing but GC-reclaimable bytes behind.
    const put = await this.blockPut(bytes, codec);
    if (put.Key !== cid) {
      throw new PinCidMismatchError(cid, put.Key);
    }
    await this.pinAdd(cid);
  }

  async unpin(cid: string): Promise<boolean> {
    if (!this.apiUrl) {
      return false;
    }
    try {
      const response = await fetch(
        `${this.apiUrl}/api/v0/pin/rm?arg=${encodeURIComponent(cid)}&recursive=true`,
        { method: 'POST', signal: AbortSignal.timeout(5000) }
      );
      if (!response.ok) {
        this.logger.warn(`pin/rm for ${cid} returned ${response.status}`);
        return false;
      }
      return true;
    } catch (error) {
      // Best-effort: bookkeeping already dropped the row, so a Kubo hiccup
      // must not fail the caller's retire. Log and report no physical release.
      this.logger.warn(`pin/rm failed for ${cid}: ${String(error)}`);
      return false;
    }
  }

  /** Write one block under `codec` + BLAKE3-256, unpinned. */
  private async blockPut(bytes: Uint8Array, codec: string): Promise<KuboBlockPutResult> {
    const form = new FormData();
    // Copy into an ArrayBuffer-backed view so the Blob part type is exact. Kubo
    // requires the part to carry a filename, so pass one explicitly.
    form.append('data', new Blob([new Uint8Array(bytes)]), 'blob');
    const body = await this.rpc(
      `block/put?cid-codec=${encodeURIComponent(codec)}&mhtype=blake3&mhlen=32&pin=false`,
      form
    );
    // Kubo streams newline-delimited JSON; one block yields one final object.
    const lines = body.trim().split('\n').filter(Boolean);
    const last = lines[lines.length - 1];
    if (!last) {
      throw new ServiceUnavailableException('Kubo block/put returned no result');
    }
    return JSON.parse(last) as KuboBlockPutResult;
  }

  private async pinAdd(cid: string): Promise<void> {
    await this.rpc(`pin/add?arg=${encodeURIComponent(cid)}&recursive=false`);
  }

  private async rpc(path: string, body?: FormData): Promise<string> {
    if (!this.apiUrl) {
      throw new ServiceUnavailableException('Hosted pin store not configured');
    }
    const response = await fetch(`${this.apiUrl}/api/v0/${path}`, {
      method: 'POST',
      body,
      signal: AbortSignal.timeout(30_000),
    });
    if (!response.ok) {
      throw new ServiceUnavailableException(
        `Kubo ${path.split('?')[0]} failed: ${response.status}`
      );
    }
    return response.text();
  }
}
