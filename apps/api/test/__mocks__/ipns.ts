/**
 * Mock for ipns ESM module
 * This mock is used for tests that don't directly test IPNS record parsing
 */

export const unmarshalIPNSRecord = jest.fn().mockReturnValue({
  value: '/ipfs/bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi',
  sequence: 0n,
});
