/**
 * Mock Delegated Routing Service for E2E Testing
 *
 * Implements the IPFS delegated routing API for IPNS records:
 * - PUT /routing/v1/ipns/{name} - Store an IPNS record
 * - GET /routing/v1/ipns/{name} - Retrieve an IPNS record
 *
 * Records are stored in-memory and reset when the service restarts.
 * This allows E2E tests to run without polluting the public IPFS DHT
 * and avoids sequence number conflicts from repeated test runs.
 */
export {};
