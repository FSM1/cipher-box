/**
 * What the routing front owes a browser, watched on the wire (blueprint/api.md
 * Egress, `docker/Caddyfile`): a record PUT must reach it, and a read answer
 * must carry no cache lifetime — someguy labels a missing name cacheable for
 * two days, so a vacancy probe's answer would outlive the publish that fills it.
 */

import type { Page, Request } from '@playwright/test';

export interface RoutingFrontLog {
  /** Record PUTs the front never answered 2xx, with the network error or the status. */
  readonly refusedPublishes: string[];
  /** Read answers the browser was told it may reuse, with the header. */
  readonly cacheableReads: string[];
  /** Every read answer seen, so an assertion can say it saw nothing at all. */
  readonly reads: string[];
  /** Record PUTs the front answered 2xx, which is the only landed publish. */
  readonly publishes: string[];
}

/** The routing front beside the app front; `E2E_ROUTING_URL` overrides it. */
export function routingOrigin(baseUrl: string): string {
  const override = process.env.E2E_ROUTING_URL?.trim();
  if (override) return override.replace(/\/+$/, '');
  const url = new URL(baseUrl);
  url.host = url.host.replace(/^app-/, 'routing-');
  return url.origin;
}

/** A lifetime the browser may serve from, rather than a re-fetch. */
export function isCacheable(cacheControl: string | null): boolean {
  if (cacheControl === null) return true;
  const directives = cacheControl.toLowerCase();
  if (/(^|[\s,])no-store([\s,]|$)/.test(directives)) return false;
  // One delimiter group over both names: an alternation of whole patterns lets
  // the second name match inside a longer vendor directive.
  return /(?:^|[\s,])(?:(?:s-)?max-age|stale-while-revalidate)=[1-9]\d*(?=$|[\s,])/.test(
    directives
  );
}

/** Records what the routing front answers for the rest of the test. */
export function watchRoutingFront(page: Page, routingOrigin: string): RoutingFrontLog {
  const log: RoutingFrontLog = {
    refusedPublishes: [],
    cacheableReads: [],
    reads: [],
    publishes: [],
  };
  const mine = (url: string) => url.startsWith(routingOrigin);
  /**
   * Publishes the front answered 2xx. The record transport never reads a
   * publish answer's body, so the browser drops it and reports the request as
   * failed after the answer. The record is on the front either way.
   */
  const landed = new WeakSet<Request>();

  page.on('response', (response) => {
    const request = response.request();
    if (!mine(request.url())) return;
    if (request.method() === 'PUT') {
      // The front can answer a publish and still refuse it; only a 2xx lands.
      const status = response.status();
      if (status >= 200 && status < 300) {
        landed.add(request);
        log.publishes.push(request.url());
      } else {
        log.refusedPublishes.push(`${request.url()} status: ${status}`);
      }
      return;
    }
    if (request.method() !== 'GET') return;
    const cacheControl = response.headers()['cache-control'] ?? null;
    log.reads.push(request.url());
    if (isCacheable(cacheControl)) {
      log.cacheableReads.push(`${request.url()} cache-control: ${cacheControl}`);
    }
  });

  page.on('requestfailed', (request) => {
    if (!mine(request.url()) || request.method() !== 'PUT' || landed.has(request)) return;
    log.refusedPublishes.push(`${request.url()} ${request.failure()?.errorText ?? ''}`);
  });

  return log;
}
