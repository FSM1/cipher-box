import { apiClient } from './client';

type LoginRequest = {
  idToken: string;
  publicKey: string;
  loginType: 'social' | 'external_wallet' | 'corekit';
  /** ADR-001: Wallet address for external wallet JWT verification */
  walletAddress?: string;
  /** ADR-001: Key derivation version for external wallet users */
  derivationVersion?: number;
};

type LoginResponse = {
  accessToken: string;
  isNewUser: boolean;
};

type TokenResponse = {
  accessToken: string;
  email?: string;
};

/** Response from CipherBox identity provider endpoints */
type IdentityTokenResponse = {
  idToken: string;
  userId: string;
  isNewUser: boolean;
};

export type AuthMethod = {
  id: string;
  type: 'google' | 'apple' | 'github' | 'email_passwordless' | 'external_wallet';
  identifier: string;
  lastUsedAt: string | null;
  createdAt: string;
};

type LinkMethodRequest = {
  idToken: string;
  loginType: 'social' | 'external_wallet';
};

export const authApi = {
  /**
   * Authenticate user with Web3Auth ID token.
   * Backend verifies the idToken with appropriate JWKS endpoint based on loginType.
   * Refresh token is stored in HTTP-only cookie automatically.
   */
  login: async (data: LoginRequest): Promise<LoginResponse> => {
    const response = await apiClient.post<LoginResponse>('/auth/login', data);
    return response.data;
  },

  /**
   * Refresh access token using HTTP-only refresh token cookie.
   * The refresh token is automatically sent via withCredentials: true.
   * New refresh token is set in HTTP-only cookie by the backend.
   */
  refresh: async (): Promise<TokenResponse> => {
    const response = await apiClient.post<TokenResponse>('/auth/refresh');
    return response.data;
  },

  /**
   * Logout and invalidate refresh token.
   * Clears HTTP-only cookie on backend.
   */
  logout: async (): Promise<void> => {
    await apiClient.post('/auth/logout');
  },

  /**
   * Get all linked auth methods for the current user.
   */
  getMethods: async (): Promise<AuthMethod[]> => {
    const response = await apiClient.get<AuthMethod[]>('/auth/methods');
    return response.data;
  },

  /**
   * Link a new auth method to the current user account.
   * The new auth method's publicKey must match the user's publicKey
   * (via Web3Auth group connections).
   */
  linkMethod: async (data: LinkMethodRequest): Promise<AuthMethod[]> => {
    const response = await apiClient.post<AuthMethod[]>('/auth/link', data);
    return response.data;
  },

  /**
   * Unlink an auth method from the current user account.
   * Cannot unlink the last remaining auth method.
   */
  unlinkMethod: async (methodId: string): Promise<void> => {
    await apiClient.post('/auth/unlink', { methodId });
  },

  // --- CipherBox Identity Provider endpoints (Plan 12-01) ---

  /** Get CipherBox identity JWT via Google OAuth token */
  identityGoogle: async (googleIdToken: string): Promise<IdentityTokenResponse> => {
    const response = await apiClient.post<IdentityTokenResponse>('/auth/identity/google', {
      idToken: googleIdToken,
    });
    return response.data;
  },

  /** Send email OTP */
  identityEmailSendOtp: async (email: string): Promise<{ success: boolean }> => {
    const response = await apiClient.post<{ success: boolean }>('/auth/identity/email/send-otp', {
      email,
    });
    return response.data;
  },

  /** Verify email OTP and get CipherBox identity JWT */
  identityEmailVerify: async (email: string, otp: string): Promise<IdentityTokenResponse> => {
    const response = await apiClient.post<IdentityTokenResponse>(
      '/auth/identity/email/verify-otp',
      {
        email,
        otp,
      }
    );
    return response.data;
  },
};
