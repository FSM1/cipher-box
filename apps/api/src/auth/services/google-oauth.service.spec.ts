import { UnauthorizedException } from '@nestjs/common';
import * as jose from 'jose';
import { GoogleOAuthService } from './google-oauth.service';

describe('GoogleOAuthService', () => {
  let service: GoogleOAuthService;

  beforeEach(() => {
    service = new GoogleOAuthService();
    jest.clearAllMocks();
  });

  describe('verifyGoogleToken', () => {
    it('should return email and sub from valid Google token', async () => {
      (jose.jwtVerify as jest.Mock).mockResolvedValue({
        payload: {
          email: 'user@gmail.com',
          sub: 'google-user-123',
          name: 'Test User',
          email_verified: true,
        },
      });

      const result = await service.verifyGoogleToken('valid-google-token');

      expect(result.email).toBe('user@gmail.com');
      expect(result.sub).toBe('google-user-123');
      expect(result.name).toBe('Test User');
    });

    it('should throw UnauthorizedException on invalid token', async () => {
      (jose.jwtVerify as jest.Mock).mockRejectedValue(new Error('token expired'));

      await expect(service.verifyGoogleToken('expired-token')).rejects.toThrow(
        UnauthorizedException
      );
    });

    it('should throw UnauthorizedException if email claim is missing', async () => {
      (jose.jwtVerify as jest.Mock).mockResolvedValue({
        payload: { sub: 'google-user-123' },
      });

      await expect(service.verifyGoogleToken('no-email-token')).rejects.toThrow(
        UnauthorizedException
      );
      await expect(service.verifyGoogleToken('no-email-token')).rejects.toThrow(
        'Google token missing email claim'
      );
    });

    it('should throw UnauthorizedException if sub claim is missing', async () => {
      (jose.jwtVerify as jest.Mock).mockResolvedValue({
        payload: { email: 'user@gmail.com' },
      });

      await expect(service.verifyGoogleToken('no-sub-token')).rejects.toThrow(
        UnauthorizedException
      );
      await expect(service.verifyGoogleToken('no-sub-token')).rejects.toThrow(
        'Google token missing sub claim'
      );
    });

    it('should reuse JWKS instance across calls', async () => {
      (jose.jwtVerify as jest.Mock).mockResolvedValue({
        payload: { email: 'user@gmail.com', sub: '123' },
      });

      await service.verifyGoogleToken('token1');
      await service.verifyGoogleToken('token2');

      // createRemoteJWKSet should only be called once (lazy init + reuse)
      expect(jose.createRemoteJWKSet).toHaveBeenCalledTimes(1);
    });

    it('should return undefined name when not present', async () => {
      (jose.jwtVerify as jest.Mock).mockResolvedValue({
        payload: { email: 'user@gmail.com', sub: '123' },
      });

      const result = await service.verifyGoogleToken('token');

      expect(result.name).toBeUndefined();
    });
  });
});
