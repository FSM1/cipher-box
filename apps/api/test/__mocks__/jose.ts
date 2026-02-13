// Mock for jose ESM module to avoid Jest transformation issues
export const createRemoteJWKSet = jest.fn(() => jest.fn());
export const createLocalJWKSet = jest.fn(() => jest.fn());
export const jwtVerify = jest.fn();
export const importPKCS8 = jest.fn().mockResolvedValue('mock-private-key');
export const generateKeyPair = jest.fn().mockResolvedValue({
  publicKey: 'mock-public-key',
  privateKey: 'mock-private-key',
});
export const exportJWK = jest.fn().mockResolvedValue({ kty: 'RSA', n: 'mock-n', e: 'AQAB' });

export class SignJWT {
  setProtectedHeader() {
    return this;
  }
  setIssuer() {
    return this;
  }
  setAudience() {
    return this;
  }
  setIssuedAt() {
    return this;
  }
  setExpirationTime() {
    return this;
  }
  async sign() {
    return 'mock-jwt-token';
  }
}
