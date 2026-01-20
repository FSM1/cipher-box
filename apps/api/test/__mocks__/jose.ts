// Mock for jose ESM module to avoid Jest transformation issues
export const createRemoteJWKSet = jest.fn(() => jest.fn());
export const jwtVerify = jest.fn();
