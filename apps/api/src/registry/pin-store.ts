import { Injectable, Logger, ServiceUnavailableException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

/**
 * The hosted pin-store port (blueprint/api.md, Content plane + "physical unpin
 * fires at global refcount zero" — v1's `guardedUnpin` survives). It owns every
 * side effect against CipherBox Kubo: computing a content CID, durably pinning
 * bytes on the ingress path, and releasing bytes at refcount zero. The registry
 * and content services own the row DECISIONS; this port owns the byte effects.
 *
 * `unpin` is a best-effort liveness optimization, not a correctness dependency:
 * the per-account row bookkeeping is the source of truth, so a failed or
 * unconfigured unpin never fails a retire — the CID lingers and decays from the
 * pin store's own GC. It returns whether the CID was physically released (`true`)
 * so callers report a truthful unpin count; a no-op or swallowed failure returns
 * `false` (never throws). `hash`/`pin` are the ingress byte path; a consumer that
 * only retires (the registry) never calls them, so the base rejects rather than
 * forcing every unpin-only fake to stub the byte methods.
 */
@Injectable()
export abstract class PinStore {
  abstract unpin(cid: string): Promise<boolean>;

  /** Content CID of `bytes` with no durable pin (the pre-commit CID derivation). */
  hash(_bytes: Uint8Array): Promise<string> {
    throw new ServiceUnavailableException('Hosted pin store does not support content hashing');
  }

  /** Durably pin `bytes`, returning the pinned CID (the post-commit byte effect). */
  pin(_bytes: Uint8Array): Promise<string> {
    throw new ServiceUnavailableException('Hosted pin store does not support pinning');
  }
}

/** One Kubo `add` result line; only `Hash` is consumed. */
interface KuboAddResult {
  Hash: string;
}

/**
 * Default hosted implementation over the Kubo RPC API (`KUBO_API_URL`). `hash`
 * and `pin` share identical `add` parameters so the pre-commit CID always
 * matches the pinned CID (content addressing is deterministic). `unpin` no-ops
 * when Kubo is unconfigured (unit tests, BYO-only deployments); the byte path
 * fails closed instead, since an upload with no pin store cannot be durable.
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

  override async hash(bytes: Uint8Array): Promise<string> {
    // `only-hash` chunks and hashes without writing blocks — no durable effect.
    return (await this.add(bytes, 'only-hash=true')).Hash;
  }

  override async pin(bytes: Uint8Array): Promise<string> {
    return (await this.add(bytes, 'pin=true')).Hash;
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

  private async add(bytes: Uint8Array, params: string): Promise<KuboAddResult> {
    if (!this.apiUrl) {
      throw new ServiceUnavailableException('Hosted pin store not configured');
    }
    const form = new FormData();
    // Copy into an ArrayBuffer-backed view so the Blob part type is exact. Kubo
    // requires the part to carry a filename, so pass one explicitly.
    form.append('file', new Blob([new Uint8Array(bytes)]), 'blob');
    const response = await fetch(`${this.apiUrl}/api/v0/add?${params}`, {
      method: 'POST',
      body: form,
      signal: AbortSignal.timeout(30_000),
    });
    if (!response.ok) {
      throw new ServiceUnavailableException(`Kubo add failed: ${response.status}`);
    }
    // Kubo streams newline-delimited JSON; a single file yields one final object.
    const lines = (await response.text()).trim().split('\n').filter(Boolean);
    const last = lines[lines.length - 1];
    if (!last) {
      throw new ServiceUnavailableException('Kubo add returned no result');
    }
    return JSON.parse(last) as KuboAddResult;
  }
}
