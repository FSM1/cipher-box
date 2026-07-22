import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

const IPNS_RECORD_MEDIA_TYPE = 'application/vnd.ipfs.ipns-record';
const DEFAULT_TIMEOUT_MS = 10_000;

/**
 * Ceiling on a resolved `/routing/v1` body. An IPNS record
 * (application/vnd.ipfs.ipns-record) is metadata-scale — a signed name→value
 * record of ~10 KB by someguy/Kubo discipline — so 64 KiB is a generous cap.
 * fetch is time-bounded (AbortSignal.timeout) but NOT size-bounded, so without
 * this a misbehaving/compromised routing endpoint could stream a multi-GB body
 * into API heap and into record_cache (defense-in-depth, #702).
 */
const MAX_RECORD_BYTES = 64 * 1024;

/**
 * The republisher's `/routing/v1` byte mover (blueprint/api.md: resolve from the
 * network, re-PUT the same bytes keyless). A dumb transport, mirroring the
 * client seam's doctrine: it never inspects, decodes, verifies, or reorders
 * records — it only addresses a name and moves opaque signed bytes. Absence is
 * `null`; a rejected promise is a transport-level failure the walk treats as a
 * resolve failure. Injected so tests substitute an in-memory fake.
 */
@Injectable()
export abstract class RecordTransport {
  /** Resolve the latest record bytes for a name; null if the network has none. */
  abstract resolve(ipnsName: string): Promise<Buffer | null>;
  /** Re-PUT opaque record bytes keyless (the records carry client-signed EOLs). */
  abstract republish(ipnsName: string, record: Buffer): Promise<void>;

  /**
   * Whether a routing endpoint is wired up. False in BYO-only deploys with no
   * `ROUTING_V1_URL`, where the walk would resolve every name to null — the task
   * checks this and skips the sweep rather than firing a resolve-failure alert
   * for every name each cadence.
   */
  get configured(): boolean {
    return true;
  }
}

/**
 * Default HTTP transport against a `/routing/v1` endpoint (self-hosted someguy in
 * production, the hermetic mock store in CI). The endpoint is an accelerator, so
 * a failed resolve or re-PUT is never fatal — it surfaces as a resolve failure /
 * liveness alert, never a correctness break. Absent `ROUTING_V1_URL` the resolve
 * returns null and the re-PUT no-ops (unit deploys, BYO-only).
 */
@Injectable()
export class RoutingV1RecordTransport extends RecordTransport {
  private readonly logger = new Logger(RecordTransport.name);
  private readonly baseUrl: string | undefined;
  private readonly timeoutMs: number;

  constructor(configService: ConfigService) {
    super();
    const raw = configService.get<string>('ROUTING_V1_URL');
    this.baseUrl = raw && raw.trim() ? raw.replace(/\/+$/, '') : undefined;
    const timeout = Number(configService.get('ROUTING_V1_TIMEOUT_MS'));
    this.timeoutMs = Number.isInteger(timeout) && timeout > 0 ? timeout : DEFAULT_TIMEOUT_MS;
  }

  override get configured(): boolean {
    return this.baseUrl !== undefined;
  }

  async resolve(ipnsName: string): Promise<Buffer | null> {
    if (!this.baseUrl) {
      return null;
    }
    const response = await fetch(this.recordUrl(ipnsName), {
      method: 'GET',
      headers: { Accept: IPNS_RECORD_MEDIA_TYPE },
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (response.status === 404) {
      return null;
    }
    if (!response.ok) {
      throw new Error(`routing GET ${response.status} for ${ipnsName}`);
    }
    // Reject an honestly-declared oversized body before reading any of it.
    const declared = response.headers.get('content-length');
    if (declared !== null && Number(declared) > MAX_RECORD_BYTES) {
      // Release the connection instead of leaking an unread body stream.
      await response.body?.cancel();
      throw new Error(`routing GET body ${declared}B exceeds ${MAX_RECORD_BYTES}B for ${ipnsName}`);
    }
    return this.readCapped(response, ipnsName);
  }

  /**
   * Read the body enforcing the cap as bytes arrive, so heap stays bounded to
   * ~the cap plus one chunk even when Content-Length is absent or lies (#722).
   * Buffering the whole body first would let a misbehaving routing endpoint spike
   * heap to GBs before any post-facto assert could reject it.
   */
  private async readCapped(response: Response, ipnsName: string): Promise<Buffer> {
    const reader = response.body?.getReader();
    if (!reader) {
      return Buffer.alloc(0);
    }
    const chunks: Buffer[] = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      if (!value) {
        continue;
      }
      total += value.byteLength;
      if (total > MAX_RECORD_BYTES) {
        await reader.cancel();
        throw new Error(`routing GET body exceeds ${MAX_RECORD_BYTES}B for ${ipnsName}`);
      }
      chunks.push(Buffer.from(value));
    }
    return Buffer.concat(chunks);
  }

  async republish(ipnsName: string, record: Buffer): Promise<void> {
    if (!this.baseUrl) {
      this.logger.debug?.(`ROUTING_V1_URL unset; skipping re-PUT for ${ipnsName}`);
      return;
    }
    const response = await fetch(this.recordUrl(ipnsName), {
      method: 'PUT',
      headers: { 'Content-Type': IPNS_RECORD_MEDIA_TYPE },
      body: new Uint8Array(record),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!response.ok) {
      throw new Error(`routing PUT ${response.status} for ${ipnsName}`);
    }
  }

  private recordUrl(ipnsName: string): string {
    return `${this.baseUrl}/routing/v1/ipns/${encodeURIComponent(ipnsName)}`;
  }
}
