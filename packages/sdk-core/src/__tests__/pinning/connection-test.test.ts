import { describe, it, expect, vi, beforeEach } from 'vitest';
import { testConnection } from '../../pinning/connection-test';

// Mock global fetch
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

describe('testConnection', () => {
  const endpoint = 'http://localhost:5001';

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('detects Kubo when /api/v0/id returns 200 with AgentVersion', async () => {
    mockFetch.mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ AgentVersion: 'kubo/0.34.0' }),
    });

    const result = await testConnection(endpoint);

    expect(result.success).toBe(true);
    expect(result.protocol).toBe('kubo');
    expect(result.version).toBe('kubo/0.34.0');
    expect(result.latencyMs).toBeGreaterThanOrEqual(0);

    // Verify it called /api/v0/id with POST
    expect(mockFetch).toHaveBeenCalledWith(
      `${endpoint}/api/v0/id`,
      expect.objectContaining({ method: 'POST' })
    );
  });

  it('detects PSA when /api/v0/id fails and /pins returns 200', async () => {
    // First call: Kubo probe returns non-200
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 404,
    });

    // Second call: PSA probe returns 200
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ count: 0, results: [] }),
    });

    const result = await testConnection(endpoint, 'my-token');

    expect(result.success).toBe(true);
    expect(result.protocol).toBe('psa');
    expect(result.latencyMs).toBeGreaterThanOrEqual(0);
  });

  it('reports auth failure when PSA returns 401', async () => {
    // Kubo probe fails
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 404,
    });

    // PSA probe returns 401
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 401,
    });

    const result = await testConnection(endpoint, 'bad-token');

    expect(result.success).toBe(false);
    expect(result.protocol).toBe('psa');
    expect(result.error).toContain('authentication');
  });

  it('reports CORS error with Kubo instructions when fetch throws TypeError', async () => {
    // Kubo probe throws TypeError (CORS)
    mockFetch.mockRejectedValueOnce(new TypeError('Failed to fetch'));

    const result = await testConnection(endpoint);

    expect(result.success).toBe(false);
    expect(result.corsError).toBe(true);
    expect(result.corsInstructions).toContain('ipfs config');
    expect(result.error).toContain('CORS');
  });

  it('reports CORS error with PSA instructions when both probes fail with TypeError', async () => {
    // Kubo probe: non-CORS error (e.g., DNS failure returns null from probeKubo)
    mockFetch.mockRejectedValueOnce(new Error('ECONNREFUSED'));

    // PSA probe: CORS TypeError
    mockFetch.mockRejectedValueOnce(new TypeError('Failed to fetch'));

    const result = await testConnection(endpoint, 'token');

    expect(result.success).toBe(false);
    expect(result.corsError).toBe(true);
    expect(result.corsInstructions).toContain('pinning service dashboard');
  });

  it('reports generic failure when both probes return non-200 non-TypeError', async () => {
    // Kubo probe returns 500
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 500,
    });

    // PSA probe returns 500
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 500,
    });

    const result = await testConnection(endpoint);

    expect(result.success).toBe(false);
    expect(result.error).toContain('could not detect');
  });

  it('measures latencyMs as a positive number', async () => {
    mockFetch.mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ AgentVersion: 'kubo/0.34.0' }),
    });

    const result = await testConnection(endpoint);

    expect(typeof result.latencyMs).toBe('number');
    expect(result.latencyMs).toBeGreaterThanOrEqual(0);
  });

  it('sends Basic auth header for Kubo probe when authToken provided', async () => {
    mockFetch.mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ AgentVersion: 'kubo/0.34.0' }),
    });

    await testConnection(endpoint, 'my-basic-token');

    const kuboCallHeaders = mockFetch.mock.calls[0][1].headers;
    expect(kuboCallHeaders['Authorization']).toBe('Basic my-basic-token');
  });

  it('sends Bearer auth header for PSA probe when authToken provided', async () => {
    // Kubo probe fails
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 404,
    });

    // PSA probe succeeds
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ count: 0, results: [] }),
    });

    await testConnection(endpoint, 'my-bearer-token');

    const psaCallHeaders = mockFetch.mock.calls[1][1].headers;
    expect(psaCallHeaders['Authorization']).toBe('Bearer my-bearer-token');
  });
});
