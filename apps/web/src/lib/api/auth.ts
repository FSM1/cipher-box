import { apiClient } from './client';

type LoginRequest = {
  idToken: string;
  publicKey: string;
  loginType: 'social' | 'external_wallet';
};

type LoginResponse = {
  accessToken: string;
  isNewUser: boolean;
};

type TokenResponse = {
  accessToken: string;
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
};
