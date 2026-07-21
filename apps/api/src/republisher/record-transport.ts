import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

const IPNS_RECORD_MEDIA_TYPE = 'application/vnd.ipfs.ipns-record';
const DEFAULT_TIMEOUT_MS = 10_000;

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
    return Buffer.from(await response.arrayBuffer());
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
