import { describe, expect, it } from 'vitest';
import { errorMessage } from './errorMessage';

describe('errorMessage', () => {
  it('names the host and the status of a thrown Response, not its path or body', () => {
    const refused = new Response('{"token":"BODY-MARKER"}', { status: 500 });
    Object.defineProperty(refused, 'url', {
      value: 'https://node-1.dev-node.web3auth.io/sss/jrpc?token=QUERY-MARKER',
    });

    const line = errorMessage(refused);

    expect(line).toBe('the request to node-1.dev-node.web3auth.io failed with status 500');
    expect(line).not.toMatch(/sss|jrpc|QUERY-MARKER|BODY-MARKER/);
  });

  it('reads a Response from another realm by its shape', () => {
    expect(errorMessage({ status: 503, url: 'https://node-2.dev-node.web3auth.io/x' })).toBe(
      'the request to node-2.dev-node.web3auth.io failed with status 503'
    );
  });

  it('names no host for a Response without a url', () => {
    expect(errorMessage(new Response(null, { status: 502 }))).toBe(
      'the request to an unknown host failed with status 502'
    );
  });

  it('keeps the message of an Error and the text of anything else', () => {
    expect(errorMessage(new Error('refused'))).toBe('refused');
    expect(errorMessage('plain')).toBe('plain');
  });
});
