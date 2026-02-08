import { Test, TestingModule } from '@nestjs/testing';
import { UnauthorizedException } from '@nestjs/common';
import { Response, Request as ExpressRequest } from 'express';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { LoginDto } from './dto/login.dto';
import { LinkMethodDto } from './dto/link-method.dto';

describe('AuthController', () => {
  let controller: AuthController;
  let authService: jest.Mocked<AuthService>;
  let mockResponse: jest.Mocked<Response>;
  let mockWebRequest: ExpressRequest;

  const mockUser = {
    id: 'user-uuid-123',
    publicKey: '04abcd1234567890',
  };

  beforeEach(async () => {
    // Create mock AuthService
    const mockAuthService = {
      login: jest.fn(),
      refresh: jest.fn(),
      refreshByToken: jest.fn(),
      logout: jest.fn(),
      getLinkedMethods: jest.fn(),
      linkMethod: jest.fn(),
      unlinkMethod: jest.fn(),
    };

    // Create mock Response object for cookie handling
    mockResponse = {
      cookie: jest.fn(),
      clearCookie: jest.fn(),
    } as unknown as jest.Mocked<Response>;

    // Create mock web request (no X-Client-Type header)
    mockWebRequest = {
      headers: {},
    } as unknown as ExpressRequest;

    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        {
          provide: AuthService,
          useValue: mockAuthService,
        },
      ],
    })
      .overrideGuard(JwtAuthGuard)
      .useValue({ canActivate: () => true })
      .compile();

    controller = module.get<AuthController>(AuthController);
    authService = module.get(AuthService);
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  describe('login', () => {
    const loginDto: LoginDto = {
      idToken: 'mock-web3auth-token',
      publicKey: '04abcd1234567890',
      loginType: 'social',
    };

    it('should call authService.login with loginDto', async () => {
      authService.login.mockResolvedValue({
        accessToken: 'mock-access-token',
        refreshToken: 'mock-refresh-token',
        isNewUser: false,
      });

      await controller.login(loginDto, mockWebRequest, mockResponse);

      expect(authService.login).toHaveBeenCalledWith(loginDto);
      expect(authService.login).toHaveBeenCalledTimes(1);
    });

    it('should set refresh_token cookie with correct options', async () => {
      authService.login.mockResolvedValue({
        accessToken: 'mock-access-token',
        refreshToken: 'mock-refresh-token',
        isNewUser: false,
      });

      await controller.login(loginDto, mockWebRequest, mockResponse);

      expect(mockResponse.cookie).toHaveBeenCalledWith(
        'refresh_token',
        'mock-refresh-token',
        expect.objectContaining({
          httpOnly: true,
          path: '/auth',
        })
      );
    });

    it('should return accessToken and isNewUser (not refreshToken)', async () => {
      authService.login.mockResolvedValue({
        accessToken: 'mock-access-token',
        refreshToken: 'mock-refresh-token',
        isNewUser: true,
      });

      const result = await controller.login(loginDto, mockWebRequest, mockResponse);

      expect(result).toEqual({
        accessToken: 'mock-access-token',
        isNewUser: true,
      });
      expect(result).not.toHaveProperty('refreshToken');
    });

    it('should return isNewUser: false for existing users', async () => {
      authService.login.mockResolvedValue({
        accessToken: 'mock-access-token',
        refreshToken: 'mock-refresh-token',
        isNewUser: false,
      });

      const result = await controller.login(loginDto, mockWebRequest, mockResponse);

      expect(result.isNewUser).toBe(false);
    });
  });

  describe('login (desktop client)', () => {
    const loginDto: LoginDto = {
      idToken: 'mock-web3auth-token',
      publicKey: '04abcd1234567890',
      loginType: 'social',
    };

    it('should return refreshToken in body when X-Client-Type: desktop header is present', async () => {
      const desktopRequest = {
        headers: { 'x-client-type': 'desktop' },
      } as unknown as ExpressRequest;

      authService.login.mockResolvedValue({
        accessToken: 'mock-access-token',
        refreshToken: 'mock-refresh-token',
        isNewUser: false,
      });

      const result = await controller.login(loginDto, desktopRequest, mockResponse);

      expect(result).toEqual({
        accessToken: 'mock-access-token',
        refreshToken: 'mock-refresh-token',
        isNewUser: false,
      });
    });

    it('should NOT set cookie when X-Client-Type: desktop header is present', async () => {
      const desktopRequest = {
        headers: { 'x-client-type': 'desktop' },
      } as unknown as ExpressRequest;

      authService.login.mockResolvedValue({
        accessToken: 'mock-access-token',
        refreshToken: 'mock-refresh-token',
        isNewUser: false,
      });

      await controller.login(loginDto, desktopRequest, mockResponse);

      expect(mockResponse.cookie).not.toHaveBeenCalled();
    });
  });

  describe('refresh', () => {
    it('should extract refresh_token from cookies', async () => {
      const mockRequest = {
        headers: {},
        cookies: { refresh_token: 'mock-refresh-token' },
      } as unknown as ExpressRequest;

      authService.refreshByToken.mockResolvedValue({
        accessToken: 'new-access-token',
        refreshToken: 'new-refresh-token',
      });

      await controller.refresh(mockRequest, {}, mockResponse);

      expect(authService.refreshByToken).toHaveBeenCalledWith('mock-refresh-token');
    });

    it('should throw UnauthorizedException if no refresh token cookie', async () => {
      const mockRequest = {
        headers: {},
        cookies: {},
      } as unknown as ExpressRequest;

      await expect(controller.refresh(mockRequest, {}, mockResponse)).rejects.toThrow(
        UnauthorizedException
      );
      await expect(controller.refresh(mockRequest, {}, mockResponse)).rejects.toThrow(
        'No refresh token'
      );
    });

    it('should throw UnauthorizedException if cookies object is undefined', async () => {
      const mockRequest = {
        headers: {},
        cookies: undefined,
      } as unknown as ExpressRequest;

      await expect(controller.refresh(mockRequest, {}, mockResponse)).rejects.toThrow(
        UnauthorizedException
      );
    });

    it('should set new refresh_token cookie on successful refresh', async () => {
      const mockRequest = {
        headers: {},
        cookies: { refresh_token: 'old-refresh-token' },
      } as unknown as ExpressRequest;

      authService.refreshByToken.mockResolvedValue({
        accessToken: 'new-access-token',
        refreshToken: 'new-refresh-token',
      });

      await controller.refresh(mockRequest, {}, mockResponse);

      expect(mockResponse.cookie).toHaveBeenCalledWith(
        'refresh_token',
        'new-refresh-token',
        expect.objectContaining({
          httpOnly: true,
          path: '/auth',
        })
      );
    });

    it('should return only accessToken (refreshToken goes in cookie)', async () => {
      const mockRequest = {
        headers: {},
        cookies: { refresh_token: 'mock-refresh-token' },
      } as unknown as ExpressRequest;

      authService.refreshByToken.mockResolvedValue({
        accessToken: 'new-access-token',
        refreshToken: 'new-refresh-token',
      });

      const result = await controller.refresh(mockRequest, {}, mockResponse);

      expect(result).toEqual({
        accessToken: 'new-access-token',
      });
      expect(result).not.toHaveProperty('refreshToken');
    });
  });

  describe('refresh (desktop client)', () => {
    it('should read refreshToken from request body when X-Client-Type: desktop', async () => {
      const desktopRequest = {
        headers: { 'x-client-type': 'desktop' },
      } as unknown as ExpressRequest;

      authService.refreshByToken.mockResolvedValue({
        accessToken: 'new-access-token',
        refreshToken: 'new-refresh-token',
      });

      await controller.refresh(
        desktopRequest,
        { refreshToken: 'desktop-refresh-token' },
        mockResponse
      );

      expect(authService.refreshByToken).toHaveBeenCalledWith('desktop-refresh-token');
    });

    it('should return new refreshToken in body when X-Client-Type: desktop', async () => {
      const desktopRequest = {
        headers: { 'x-client-type': 'desktop' },
      } as unknown as ExpressRequest;

      authService.refreshByToken.mockResolvedValue({
        accessToken: 'new-access-token',
        refreshToken: 'new-refresh-token',
      });

      const result = await controller.refresh(
        desktopRequest,
        { refreshToken: 'desktop-refresh-token' },
        mockResponse
      );

      expect(result).toEqual({
        accessToken: 'new-access-token',
        refreshToken: 'new-refresh-token',
      });
    });

    it('should NOT set cookie when X-Client-Type: desktop', async () => {
      const desktopRequest = {
        headers: { 'x-client-type': 'desktop' },
      } as unknown as ExpressRequest;

      authService.refreshByToken.mockResolvedValue({
        accessToken: 'new-access-token',
        refreshToken: 'new-refresh-token',
      });

      await controller.refresh(
        desktopRequest,
        { refreshToken: 'desktop-refresh-token' },
        mockResponse
      );

      expect(mockResponse.cookie).not.toHaveBeenCalled();
    });

    it('should throw UnauthorizedException if desktop request has no body refreshToken', async () => {
      const desktopRequest = {
        headers: { 'x-client-type': 'desktop' },
      } as unknown as ExpressRequest;

      await expect(controller.refresh(desktopRequest, {}, mockResponse)).rejects.toThrow(
        UnauthorizedException
      );
      await expect(controller.refresh(desktopRequest, {}, mockResponse)).rejects.toThrow(
        'No refresh token'
      );
    });
  });

  describe('logout', () => {
    it('should clear refresh_token cookie with path /auth', async () => {
      const mockRequest = {
        user: mockUser,
        headers: {},
      } as unknown as Request & { user: typeof mockUser };

      authService.logout.mockResolvedValue({ success: true });

      await controller.logout(mockRequest as any, mockResponse);

      expect(mockResponse.clearCookie).toHaveBeenCalledWith('refresh_token', { path: '/auth' });
    });

    it('should call authService.logout with user.id', async () => {
      const mockRequest = {
        user: mockUser,
        headers: {},
      } as unknown as Request & { user: typeof mockUser };

      authService.logout.mockResolvedValue({ success: true });

      await controller.logout(mockRequest as any, mockResponse);

      expect(authService.logout).toHaveBeenCalledWith('user-uuid-123');
    });

    it('should return { success: true }', async () => {
      const mockRequest = {
        user: mockUser,
        headers: {},
      } as unknown as Request & { user: typeof mockUser };

      authService.logout.mockResolvedValue({ success: true });

      const result = await controller.logout(mockRequest as any, mockResponse);

      expect(result).toEqual({ success: true });
    });
  });

  describe('logout (desktop client)', () => {
    it('should NOT clear cookie when X-Client-Type: desktop', async () => {
      const mockRequest = {
        user: mockUser,
        headers: { 'x-client-type': 'desktop' },
      } as unknown as Request & { user: typeof mockUser };

      authService.logout.mockResolvedValue({ success: true });

      await controller.logout(mockRequest as any, mockResponse);

      expect(mockResponse.clearCookie).not.toHaveBeenCalled();
    });

    it('should still call authService.logout with user.id for desktop', async () => {
      const mockRequest = {
        user: mockUser,
        headers: { 'x-client-type': 'desktop' },
      } as unknown as Request & { user: typeof mockUser };

      authService.logout.mockResolvedValue({ success: true });

      const result = await controller.logout(mockRequest as any, mockResponse);

      expect(authService.logout).toHaveBeenCalledWith('user-uuid-123');
      expect(result).toEqual({ success: true });
    });
  });

  describe('getMethods', () => {
    it('should call authService.getLinkedMethods with user.id', async () => {
      const mockRequest = {
        user: mockUser,
      } as unknown as Request & { user: typeof mockUser };

      const mockMethods = [
        {
          id: 'method-1',
          type: 'google',
          identifier: 'user@example.com',
          lastUsedAt: new Date(),
          createdAt: new Date(),
        },
      ];

      authService.getLinkedMethods.mockResolvedValue(mockMethods);

      await controller.getMethods(mockRequest as any);

      expect(authService.getLinkedMethods).toHaveBeenCalledWith('user-uuid-123');
    });

    it('should return array of auth methods', async () => {
      const mockRequest = {
        user: mockUser,
      } as unknown as Request & { user: typeof mockUser };

      const mockMethods = [
        {
          id: 'method-1',
          type: 'google',
          identifier: 'user@example.com',
          lastUsedAt: new Date(),
          createdAt: new Date(),
        },
        {
          id: 'method-2',
          type: 'github',
          identifier: 'github-user',
          lastUsedAt: new Date(),
          createdAt: new Date(),
        },
      ];

      authService.getLinkedMethods.mockResolvedValue(mockMethods);

      const result = await controller.getMethods(mockRequest as any);

      expect(result).toEqual(mockMethods);
      expect(result).toHaveLength(2);
    });
  });

  describe('linkMethod', () => {
    const linkDto: LinkMethodDto = {
      idToken: 'mock-link-token',
      loginType: 'social',
    };

    it('should call authService.linkMethod with user.id and linkDto', async () => {
      const mockRequest = {
        user: mockUser,
      } as unknown as Request & { user: typeof mockUser };

      const mockMethods = [
        {
          id: 'method-1',
          type: 'google',
          identifier: 'user@example.com',
          lastUsedAt: new Date(),
          createdAt: new Date(),
        },
      ];

      authService.linkMethod.mockResolvedValue(mockMethods);

      await controller.linkMethod(mockRequest as any, linkDto);

      expect(authService.linkMethod).toHaveBeenCalledWith('user-uuid-123', linkDto);
    });

    it('should return updated methods array', async () => {
      const mockRequest = {
        user: mockUser,
      } as unknown as Request & { user: typeof mockUser };

      const mockMethods = [
        {
          id: 'method-1',
          type: 'google',
          identifier: 'user@example.com',
          lastUsedAt: new Date(),
          createdAt: new Date(),
        },
        {
          id: 'method-2',
          type: 'github',
          identifier: 'github-user',
          lastUsedAt: new Date(),
          createdAt: new Date(),
        },
      ];

      authService.linkMethod.mockResolvedValue(mockMethods);

      const result = await controller.linkMethod(mockRequest as any, linkDto);

      expect(result).toEqual(mockMethods);
    });
  });

  describe('unlinkMethod', () => {
    it('should call authService.unlinkMethod with user.id and methodId', async () => {
      const mockRequest = {
        user: mockUser,
      } as unknown as Request & { user: typeof mockUser };

      const unlinkDto = { methodId: 'method-to-unlink' };

      authService.unlinkMethod.mockResolvedValue(undefined);

      await controller.unlinkMethod(mockRequest as any, unlinkDto);

      expect(authService.unlinkMethod).toHaveBeenCalledWith('user-uuid-123', 'method-to-unlink');
    });

    it('should return { success: true }', async () => {
      const mockRequest = {
        user: mockUser,
      } as unknown as Request & { user: typeof mockUser };

      const unlinkDto = { methodId: 'method-to-unlink' };

      authService.unlinkMethod.mockResolvedValue(undefined);

      const result = await controller.unlinkMethod(mockRequest as any, unlinkDto);

      expect(result).toEqual({ success: true });
    });
  });
});
