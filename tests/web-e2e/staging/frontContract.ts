/**
 * What the routing front owes a browser, watched on the wire (blueprint/api.md
 * Egress, `docker/Caddyfile`): a record PUT must reach it, and a read answer
 * must carry no cache lifetime — someguy labels a missing name cacheable for
 * two days, so a vacancy probe's answer would outlive the publish that fills it.
 */

import type { Page } from '@playwright/test';

export interface RoutingFrontLog {
  /** Record PUTs the browser never completed, with the network error. */
  readonly refusedPublishes: string[];
  /** Read answers the browser was told it may reuse, with the header. */
  readonly cacheableReads: string[];
  /** Every read answer seen, so an assertion can say it saw nothing at all. */
  readonly reads: string[];
  readonly publishes: string[];
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

  page.on('response', (response) => {
    const request = response.request();
    if (!mine(request.url()) || request.method() !== 'GET') return;
    const cacheControl = response.headers()['cache-control'] ?? null;
    log.reads.push(request.url());
    if (isCacheable(cacheControl)) {
      log.cacheableReads.push(`${request.url()} cache-control: ${cacheControl}`);
    }
  });

  page.on('requestfinished', (request) => {
    if (mine(request.url()) && request.method() === 'PUT') log.publishes.push(request.url());
  });

  page.on('requestfailed', (request) => {
    if (!mine(request.url()) || request.method() !== 'PUT') return;
    log.refusedPublishes.push(`${request.url()} ${request.failure()?.errorText ?? ''}`);
  });

  return log;
}
