import { ConfigService } from '@nestjs/config';
import * as jose from 'jose';
import { JwtIssuerService } from './jwt-issuer.service';

describe('JwtIssuerService', () => {
  let service: JwtIssuerService;
  let configService: { get: jest.Mock };

  beforeEach(() => {
    configService = { get: jest.fn() };
    service = new JwtIssuerService(configService as unknown as ConfigService);
    jest.clearAllMocks();
  });

  describe('onModuleInit', () => {
    it('should generate ephemeral keypair when IDENTITY_JWT_PRIVATE_KEY not set in dev', async () => {
      configService.get.mockImplementation((key: string) => {
        if (key === 'IDENTITY_JWT_PRIVATE_KEY') return undefined;
        if (key === 'NODE_ENV') return 'development';
        return undefined;
      });

      await service.onModuleInit();

      expect(jose.generateKeyPair).toHaveBeenCalledWith('RS256', { modulusLength: 2048 });
      expect(jose.exportJWK).toHaveBeenCalledWith('mock-public-key');
    });

    it('should throw in production when IDENTITY_JWT_PRIVATE_KEY not set', async () => {
      configService.get.mockImplementation((key: string) => {
        if (key === 'IDENTITY_JWT_PRIVATE_KEY') return undefined;
        if (key === 'NODE_ENV') return 'production';
        return undefined;
      });

      await expect(service.onModuleInit()).rejects.toThrow(
        'IDENTITY_JWT_PRIVATE_KEY must be set in production'
      );
    });

    it('should load keypair from env when IDENTITY_JWT_PRIVATE_KEY is set', async () => {
      const rawPem = '-----BEGIN PRIVATE KEY-----\nmock\n-----END PRIVATE KEY-----';
      const base64Pem = Buffer.from(rawPem).toString('base64');
      configService.get.mockReturnValue(base64Pem);

      await service.onModuleInit();

      expect(jose.importPKCS8).toHaveBeenCalledWith(rawPem, 'RS256', {
        extractable: true,
      });
      expect(jose.exportJWK).toHaveBeenCalledWith('mock-private-key');
    });
  });

  describe('getJwksData', () => {
    it('should return JWKS with public key after init', async () => {
      configService.get.mockReturnValue(undefined);
      await service.onModuleInit();

      const jwks = service.getJwksData();

      expect(jwks.keys).toHaveLength(1);
      expect(jwks.keys[0]).toEqual(
        expect.objectContaining({
          kid: 'cipherbox-identity-1',
          alg: 'RS256',
          use: 'sig',
        })
      );
    });
  });

  describe('signIdentityJwt', () => {
    it('should sign JWT with user ID', async () => {
      configService.get.mockReturnValue(undefined);
      await service.onModuleInit();

      const jwt = await service.signIdentityJwt('user-123');

      expect(jwt).toBe('mock-jwt-token');
    });

    it('should sign JWT with email when provided', async () => {
      configService.get.mockReturnValue(undefined);
      await service.onModuleInit();

      const jwt = await service.signIdentityJwt('user-123', 'test@example.com');

      expect(jwt).toBe('mock-jwt-token');
    });
  });
});
