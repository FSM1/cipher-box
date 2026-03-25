/**
 * Auth API adapter -- thin wrapper over @cipherbox/api-client generated functions.
 *
 * Keeps the `authApi.foo()` call style used by useAuth.ts and web3auth/hooks.ts
 * while delegating all HTTP transport to the shared api-client package.
 */
import {
  authControllerLogin,
  authControllerRefresh,
  authControllerLogout,
  authControllerGetMethods,
  authControllerLinkMethod,
  authControllerUnlinkMethod,
  authControllerDeleteAccount,
  identityControllerGoogleLogin,
  identityControllerSendOtp,
  identityControllerVerifyOtp,
  identityControllerGetWalletNonce,
  identityControllerWalletLogin,
} from '@cipherbox/api-client';
import type {
  AuthMethodResponseDto,
  LoginResponseDto,
  TokenResponseDto,
  IdentityTokenResponseDto,
  SendOtpResponseDto,
  IdentityControllerGetWalletNonce200,
  LogoutResponseDto,
  UnlinkMethodResponseDto,
  DeleteAccountResponseDto,
} from '@cipherbox/api-client';

// Re-export model type under original alias for backward compatibility
export type AuthMethod = AuthMethodResponseDto;

// Shared in-flight refresh promise — prevents concurrent callers from
// each issuing their own POST /auth/refresh (which rotates the token,
// causing later concurrent calls to fail with 401).
let refreshPromise: Promise<TokenResponseDto> | null = null;

export const authApi = {
  /**
   * Authenticate user with Web3Auth ID token.
   * Backend verifies the idToken with appropriate JWKS endpoint based on loginType.
   * Refresh token is stored in HTTP-only cookie automatically.
   */
  login: (data: {
    idToken: string;
    publicKey: string;
    loginType: 'corekit';
  }): Promise<LoginResponseDto> => authControllerLogin(data),

  /**
   * Refresh access token using HTTP-only refresh token cookie.
   * The refresh token is automatically sent via withCredentials: true.
   * New refresh token is set in HTTP-only cookie by the backend.
   *
   * Deduplicated: concurrent callers share a single in-flight request.
   * On page reload, multiple React effects and Axios interceptors can
   * call refresh simultaneously. Without deduplication, the first response
   * rotates the refresh token, causing later concurrent calls to fail with 401.
   */
  refresh: (): Promise<TokenResponseDto> => {
    if (!refreshPromise) {
      refreshPromise = authControllerRefresh({}).finally(() => {
        refreshPromise = null;
      });
    }
    return refreshPromise;
  },

  /**
   * Logout and invalidate refresh token.
   * Clears HTTP-only cookie on backend.
   */
  logout: (): Promise<LogoutResponseDto> => authControllerLogout(),

  /**
   * Get all linked auth methods for the current user.
   */
  getMethods: (): Promise<AuthMethodResponseDto[]> => authControllerGetMethods(),

  /**
   * Link a new auth method to the current user account.
   */
  linkMethod: (data: {
    idToken: string;
    loginType: 'google' | 'email' | 'wallet';
    walletAddress?: string;
    siweMessage?: string;
    siweSignature?: string;
  }): Promise<AuthMethodResponseDto[]> => authControllerLinkMethod(data),

  /**
   * Unlink an auth method from the current user account.
   * Cannot unlink the last remaining auth method.
   */
  unlinkMethod: (methodId: string): Promise<UnlinkMethodResponseDto> =>
    authControllerUnlinkMethod({ methodId }),

  /**
   * Permanently delete the authenticated user's account.
   * Requires confirmation string "DELETE".
   */
  deleteAccount: (): Promise<DeleteAccountResponseDto> =>
    authControllerDeleteAccount({ confirmation: 'DELETE' }),

  // --- CipherBox Identity Provider endpoints ---

  /** Get CipherBox identity JWT via Google OAuth token */
  identityGoogle: (
    googleIdToken: string,
    intent?: 'login' | 'link'
  ): Promise<IdentityTokenResponseDto> =>
    identityControllerGoogleLogin({ idToken: googleIdToken, ...(intent && { intent }) }),

  /** Send email OTP */
  identityEmailSendOtp: (email: string): Promise<SendOtpResponseDto> =>
    identityControllerSendOtp({ email }),

  /** Verify email OTP and get CipherBox identity JWT */
  identityEmailVerify: (
    email: string,
    otp: string,
    intent?: 'login' | 'link'
  ): Promise<IdentityTokenResponseDto> =>
    identityControllerVerifyOtp({ email, otp, ...(intent && { intent }) }),

  /** Get a SIWE nonce for wallet login */
  identityWalletNonce: (): Promise<IdentityControllerGetWalletNonce200> =>
    identityControllerGetWalletNonce(),

  /** Verify SIWE wallet signature and get CipherBox identity JWT */
  identityWalletVerify: (data: {
    message: string;
    signature: string;
  }): Promise<IdentityTokenResponseDto> => identityControllerWalletLogin(data),
};
