import { Page } from '@playwright/test';

/**
 * Conflict detection test helpers.
 *
 * Simulates concurrent device publishes by calling the API publish endpoint
 * directly to increment a folder's server-side sequence number, making the
 * web client's local sequence stale.
 */

/**
 * Bump the server-side sequence number for a folder IPNS record.
 *
 * This simulates another device publishing to the same folder by calling the
 * API publish endpoint without an expectedSequenceNumber (backward-compatible
 * unconditional publish). The server increments the sequence number, making
 * the web client's local sequence stale. The web client's next folder mutation
 * (which sends its now-stale expectedSequenceNumber) will receive a 409.
 *
 * NOTE: Uses a dummy base64 record string which generates a delegated routing
 * warning in API logs because the IPNS record is not cryptographically valid.
 * This is expected -- we only need the DB sequence bump, not a valid IPNS
 * record for DHT propagation. The API still increments the sequence number
 * and returns 200.
 *
 * @param params.page - Playwright page instance (for page.request API calls)
 * @param params.apiBaseUrl - API base URL (e.g., "http://localhost:3000")
 * @param params.accessToken - Bearer token for authenticated API calls
 * @param params.rootIpnsName - IPNS name of the root folder to bump
 * @returns The new server-side sequence number after the bump
 */
export async function bumpServerSequence(params: {
  page: Page;
  apiBaseUrl: string;
  accessToken: string;
  rootIpnsName: string;
}): Promise<{ newSequenceNumber: string }> {
  const { page, apiBaseUrl, accessToken, rootIpnsName } = params;

  // Step 1: Resolve the current CID from the root folder's IPNS record.
  // The API's DB-cached resolve is reliable and fast (no delegated routing).
  const resolveResponse = await page.request.get(
    `${apiBaseUrl}/ipns/resolve?ipnsName=${encodeURIComponent(rootIpnsName)}`,
    {
      headers: { Authorization: `Bearer ${accessToken}` },
    }
  );

  if (!resolveResponse.ok()) {
    const body = await resolveResponse.text();
    throw new Error(
      `Failed to resolve IPNS for sequence bump (${resolveResponse.status()}): ${body}`
    );
  }

  const resolved = (await resolveResponse.json()) as {
    success: boolean;
    cid: string;
    sequenceNumber: string;
  };

  if (!resolved.success || !resolved.cid) {
    throw new Error(
      `IPNS resolve returned success=false or missing CID. Is the vault initialized? Response: ${JSON.stringify(resolved)}`
    );
  }

  // Step 2: Publish with the same CID but NO expectedSequenceNumber.
  // Omitting expectedSequenceNumber uses the backward-compatible unconditional
  // publish path which always succeeds and increments the sequence by 1.
  //
  // The dummy base64 record string is intentionally invalid as an IPNS record.
  // The API will log a warning when trying to relay it to delegated-ipfs.dev,
  // but the DB sequence bump succeeds regardless.
  const dummyRecord = Buffer.from('conflict-test-dummy-record-not-a-valid-ipns-record').toString(
    'base64'
  );

  const publishResponse = await page.request.post(`${apiBaseUrl}/ipns/publish`, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    data: {
      ipnsName: rootIpnsName,
      record: dummyRecord,
      metadataCid: resolved.cid,
      // No expectedSequenceNumber -- unconditional publish to simulate another device
    },
  });

  if (!publishResponse.ok()) {
    const body = await publishResponse.text();
    throw new Error(`Failed to bump server sequence (${publishResponse.status()}): ${body}`);
  }

  const published = (await publishResponse.json()) as { sequenceNumber: string };

  return { newSequenceNumber: published.sequenceNumber };
}
