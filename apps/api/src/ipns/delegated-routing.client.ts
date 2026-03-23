import { Injectable, HttpException, HttpStatus, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { MetricsService } from '../metrics/metrics.service';

/** Typed error for non-retryable HTTP responses from the delegated routing API. */
class DelegatedRoutingHttpError extends Error {
  constructor(public readonly status: number) {
    super(`Delegated routing returned ${status}`);
    this.name = 'DelegatedRoutingHttpError';
  }
}

@Injectable()
export class DelegatedRoutingClient {
  private readonly logger = new Logger(DelegatedRoutingClient.name);
  private readonly primaryUrl: string;
  private readonly fallbackUrl: string | null;
  private readonly maxRetries = 3;
  private readonly baseDelayMs = 1000;
  private readonly maxRetryDelayMs = 30_000;
  private readonly requestTimeoutMs = 10_000;

  constructor(
    private readonly configService: ConfigService,
    private readonly metricsService: MetricsService
  ) {
    this.primaryUrl = this.configService.get<string>(
      'DELEGATED_ROUTING_URL',
      'https://delegated-ipfs.dev'
    );
    const fallback = this.configService.get<string>('DELEGATED_ROUTING_FALLBACK_URL', '');
    this.fallbackUrl = fallback || null;

    if (this.fallbackUrl) {
      this.logger.log(
        `Delegated routing: primary=${this.primaryUrl}, fallback=${this.fallbackUrl}`
      );
    } else {
      this.logger.log(`Delegated routing: ${this.primaryUrl} (no fallback configured)`);
    }
  }

  /**
   * Publish an IPNS record via the delegated routing PUT API.
   * Tries primary backend first, falls back to fallback URL if configured.
   * Throws HttpException (BAD_GATEWAY) on persistent failures across all backends.
   */
  async publish(ipnsName: string, recordBytes: Uint8Array): Promise<void> {
    const encodedName = encodeURIComponent(ipnsName);
    const path = `/routing/v1/ipns/${encodedName}`;

    try {
      await this.executePublish(this.primaryUrl + path, recordBytes, ipnsName, 'primary');
      return;
    } catch (primaryError) {
      if (!this.fallbackUrl) throw primaryError;

      this.logger.warn(
        `Primary routing failed for publish ${ipnsName}, trying fallback: ${
          primaryError instanceof Error ? primaryError.message : String(primaryError)
        }`
      );
      this.metricsService.delegatedRoutingFallbacks.inc({ operation: 'publish' });
    }

    await this.executePublish(this.fallbackUrl + path, recordBytes, ipnsName, 'fallback');
  }

  /**
   * Resolve an IPNS name via the delegated routing GET API.
   * Tries primary backend first, falls back to fallback URL if configured.
   * Returns the raw record bytes, or null if the IPNS name is not found (404).
   * Throws HttpException (BAD_GATEWAY) on persistent failures across all backends.
   */
  async resolve(ipnsName: string): Promise<Uint8Array | null> {
    const encodedName = encodeURIComponent(ipnsName);
    const path = `/routing/v1/ipns/${encodedName}`;

    try {
      return await this.executeResolve(this.primaryUrl + path, ipnsName, 'primary');
    } catch (primaryError) {
      if (!this.fallbackUrl) throw primaryError;

      this.logger.warn(
        `Primary routing failed for resolve ${ipnsName}, trying fallback: ${
          primaryError instanceof Error ? primaryError.message : String(primaryError)
        }`
      );
      this.metricsService.delegatedRoutingFallbacks.inc({ operation: 'resolve' });
    }

    return this.executeResolve(this.fallbackUrl + path, ipnsName, 'fallback');
  }

  private async executePublish(
    url: string,
    recordBytes: Uint8Array,
    ipnsName: string,
    backend: string
  ): Promise<void> {
    let lastError: Error | null = null;

    for (let attempt = 0; attempt < this.maxRetries; attempt++) {
      try {
        const { ok, status, retryAfter, errorText } = await this.fetchWithTimeout(
          url,
          {
            method: 'PUT',
            headers: {
              'Content-Type': 'application/vnd.ipfs.ipns-record',
            },
            body: recordBytes as unknown as BodyInit,
          },
          async (response) => ({
            ok: response.ok,
            status: response.status,
            retryAfter: response.headers.get('Retry-After'),
            errorText: !response.ok && response.status !== 429 ? await response.text() : '',
          })
        );

        if (ok) {
          this.logger.log(`IPNS record published successfully for ${ipnsName} via ${backend}`);
          this.metricsService.delegatedRoutingRequests.inc({
            operation: 'publish',
            backend,
            outcome: 'success',
          });
          return;
        }

        // Handle rate limiting
        if (status === 429) {
          if (attempt < this.maxRetries - 1) {
            const delayMs = this.getRetryDelayMs(retryAfter, attempt);
            this.logger.warn(`Rate limited on IPNS publish (${backend}), retrying in ${delayMs}ms`);
            await this.delay(delayMs);
          }
          continue;
        }

        // Non-retryable HTTP error
        // [SECURITY: MEDIUM-11] Log full error details but don't expose to client
        this.logger.error(
          `Delegated routing (${backend}) returned ${status} for ${ipnsName}: ${errorText}`
        );
        throw new DelegatedRoutingHttpError(status);
      } catch (error) {
        // Non-retryable HTTP error — surface immediately
        if (error instanceof DelegatedRoutingHttpError) {
          this.metricsService.delegatedRoutingRequests.inc({
            operation: 'publish',
            backend,
            outcome: 'error',
          });
          // [SECURITY: MEDIUM-11] Generic error message to avoid leaking internal details
          throw new HttpException(
            'Failed to publish IPNS record to routing network',
            HttpStatus.BAD_GATEWAY
          );
        }

        lastError = error instanceof Error ? error : new Error(String(error));

        // Exponential backoff for network errors
        if (attempt < this.maxRetries - 1) {
          const delayMs = this.baseDelayMs * Math.pow(2, attempt);
          this.logger.warn(
            `IPNS publish attempt ${attempt + 1} (${backend}) failed, retrying in ${delayMs}ms: ${lastError.message}`
          );
          await this.delay(delayMs);
        }
      }
    }

    // [SECURITY: MEDIUM-11] Log full error, return generic message
    this.logger.error(
      `Failed to publish IPNS record via ${backend} after ${this.maxRetries} attempts: ${lastError?.message}`
    );
    this.metricsService.delegatedRoutingRequests.inc({
      operation: 'publish',
      backend,
      outcome: 'error',
    });
    throw new HttpException(
      'Failed to publish IPNS record to routing network after multiple attempts',
      HttpStatus.BAD_GATEWAY
    );
  }

  private async executeResolve(
    url: string,
    ipnsName: string,
    backend: string
  ): Promise<Uint8Array | null> {
    let lastError: Error | null = null;

    for (let attempt = 0; attempt < this.maxRetries; attempt++) {
      try {
        const { ok, status, retryAfter, data, errorText } = await this.fetchWithTimeout(
          url,
          {
            method: 'GET',
            headers: {
              Accept: 'application/vnd.ipfs.ipns-record',
            },
          },
          async (response) => ({
            ok: response.ok,
            status: response.status,
            retryAfter: response.headers.get('Retry-After'),
            data: response.ok ? new Uint8Array(await response.arrayBuffer()) : null,
            errorText:
              !response.ok && response.status !== 404 && response.status !== 429
                ? await response.text()
                : '',
          })
        );

        // 404 means IPNS name not found - not an error
        if (status === 404) {
          this.logger.debug(`IPNS name not found via ${backend}: ${ipnsName}`);
          this.metricsService.delegatedRoutingRequests.inc({
            operation: 'resolve',
            backend,
            outcome: 'not_found',
          });
          return null;
        }

        if (ok) {
          this.metricsService.delegatedRoutingRequests.inc({
            operation: 'resolve',
            backend,
            outcome: 'success',
          });
          return data;
        }

        // Handle rate limiting
        if (status === 429) {
          if (attempt < this.maxRetries - 1) {
            const delayMs = this.getRetryDelayMs(retryAfter, attempt);
            this.logger.warn(`Rate limited on IPNS resolve (${backend}), retrying in ${delayMs}ms`);
            await this.delay(delayMs);
          }
          continue;
        }

        // Non-retryable error
        // [SECURITY: MEDIUM-11] Log full error details but don't expose to client
        this.logger.error(
          `Delegated routing (${backend}) resolution returned ${status} for ${ipnsName}: ${errorText}`
        );
        throw new DelegatedRoutingHttpError(status);
      } catch (error) {
        // Re-throw HttpException immediately (e.g., parsing errors) - don't retry
        if (error instanceof HttpException) {
          throw error;
        }

        // Non-retryable HTTP error — surface immediately
        if (error instanceof DelegatedRoutingHttpError) {
          this.metricsService.delegatedRoutingRequests.inc({
            operation: 'resolve',
            backend,
            outcome: 'error',
          });
          // [SECURITY: MEDIUM-11] Generic error message to avoid leaking internal details
          throw new HttpException(
            'Failed to resolve IPNS name from routing network',
            HttpStatus.BAD_GATEWAY
          );
        }

        lastError = error instanceof Error ? error : new Error(String(error));

        // Exponential backoff for network errors
        if (attempt < this.maxRetries - 1) {
          const delayMs = this.baseDelayMs * Math.pow(2, attempt);
          this.logger.warn(
            `IPNS resolve attempt ${attempt + 1} (${backend}) failed, retrying in ${delayMs}ms: ${lastError.message}`
          );
          await this.delay(delayMs);
        }
      }
    }

    // [SECURITY: MEDIUM-11] Log full error, return generic message
    this.logger.error(
      `Failed to resolve IPNS name via ${backend} after ${this.maxRetries} attempts: ${lastError?.message}`
    );
    this.metricsService.delegatedRoutingRequests.inc({
      operation: 'resolve',
      backend,
      outcome: 'error',
    });
    throw new HttpException(
      'Failed to resolve IPNS name from routing network after multiple attempts',
      HttpStatus.BAD_GATEWAY
    );
  }

  private async fetchWithTimeout<T>(
    url: string,
    init: RequestInit,
    consume: (response: Response) => Promise<T>
  ): Promise<T> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.requestTimeoutMs);
    try {
      const response = await fetch(url, { ...init, signal: controller.signal });
      return await consume(response);
    } finally {
      clearTimeout(timeout);
    }
  }

  private getRetryDelayMs(retryAfter: string | null, attempt: number): number {
    const fallback = this.baseDelayMs * Math.pow(2, attempt);
    if (!retryAfter) return Math.min(fallback, this.maxRetryDelayMs);

    const seconds = Number(retryAfter);
    if (Number.isFinite(seconds) && seconds >= 0) {
      return Math.min(seconds * 1000, this.maxRetryDelayMs);
    }

    const retryAt = Date.parse(retryAfter);
    if (!Number.isNaN(retryAt)) {
      return Math.min(Math.max(0, retryAt - Date.now()), this.maxRetryDelayMs);
    }

    return Math.min(fallback, this.maxRetryDelayMs);
  }

  private delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
