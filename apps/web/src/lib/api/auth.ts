import { apiClient } from './client';

type LoginRequest = {
  idToken: string;
  publicKey: string;
  loginType: 'social' | 'external_wallet';
};

type LoginResponse = {
  accessToken: string;
  refreshToken: string;
  isNewUser: boolean;
  teeKeys: {
    currentEpoch: number;
    currentPublicKey: string;
    previousEpoch: number | null;
    previousPublicKey: string | null;
  };
};

type TokenResponse = {
  accessToken: string;
  refreshToken: string;
};

export const authApi = {
  /**
   * Authenticate user with Web3Auth ID token.
   * Backend verifies the idToken with appropriate JWKS endpoint based on loginType.
   */
  login: async (data: LoginRequest): Promise<LoginResponse> => {
    const response = await apiClient.post<LoginResponse>('/auth/login', data);
    return response.data;
  },

  /**
   * Refresh access token using HTTP-only refresh token cookie.
   * The refresh token is automatically sent via withCredentials: true.
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
};
