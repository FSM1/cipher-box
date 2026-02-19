# Phase 2: Authentication - Research

**Researched:** 2026-01-20
**Domain:** Web3Auth integration, JWT authentication, token management
**Confidence:** HIGH

## Summary

This research covers the authentication flow for CipherBox, which uses a two-phase approach: Web3Auth for key derivation (social/email/wallet login) and the CipherBox backend for access/refresh token management. The standard stack centers on `@web3auth/modal` v10.x for frontend authentication and NestJS with `jose` library for backend JWT verification.

Key findings include critical differences in JWKS endpoints between social logins (`https://api-auth.web3auth.io/jwks`) and external wallets (`https://authjs.web3auth.io/jwks`), the importance of group connections for deriving the same keypair across auth methods, and best practices for refresh token rotation with HTTP-only cookies.

**Primary recommendation:** Use Web3Auth Modal SDK with React hooks (`@web3auth/modal/react`), verify Web3Auth JWTs using `jose` with the appropriate JWKS endpoint based on login type, and implement refresh token rotation with HTTP-only cookies for the CipherBox backend tokens.

## Standard Stack

The established libraries/tools for this domain:

### Core

| Library          | Version | Purpose                                     | Why Standard                                                    |
| ---------------- | ------- | ------------------------------------------- | --------------------------------------------------------------- |
| @web3auth/modal  | 10.10.0 | Web3Auth modal integration with React hooks | Official SDK with built-in React support, TypeScript types      |
| jose             | 5.x     | JWT verification with JWKS endpoint support | Recommended by Web3Auth docs, pure JS, works in all runtimes    |
| @nestjs/jwt      | 11.x    | JWT signing for CipherBox tokens            | NestJS ecosystem standard, integrates with Passport             |
| @nestjs/passport | 11.x    | Authentication strategies for NestJS        | Official NestJS auth solution                                   |
| passport-jwt     | 4.x     | JWT extraction and validation strategy      | Standard Passport strategy for JWT                              |
| argon2           | 0.31.x  | Refresh token hashing                       | Winner of Password Hashing Competition, more secure than bcrypt |

### Supporting

| Library               | Version | Purpose                                        | When to Use                                     |
| --------------------- | ------- | ---------------------------------------------- | ----------------------------------------------- |
| @tanstack/react-query | 5.x     | Already in project, use for auth state queries | Token refresh, user info fetching               |
| axios                 | 1.x     | HTTP client with interceptors                  | Request/response interceptors for token refresh |

### Alternatives Considered

| Instead of       | Could Use     | Tradeoff                                                         |
| ---------------- | ------------- | ---------------------------------------------------------------- |
| jose             | jsonwebtoken  | jose is more modern, works in browser, jsonwebtoken only Node.js |
| argon2           | bcrypt        | bcrypt is simpler but argon2 is more secure against GPU attacks  |
| @nestjs/passport | Custom guards | Passport provides standardized strategies, easier to extend      |

**Installation (Backend):**

```bash
pnpm add jose argon2 @nestjs/jwt @nestjs/passport passport passport-jwt
pnpm add -D @types/passport-jwt
```

**Installation (Frontend):**

```bash
pnpm add @web3auth/modal axios
```

## Architecture Patterns

### Recommended Project Structure

**Backend (apps/api/src):**

```
src/
  auth/
    auth.module.ts            # Auth module with dependencies
    auth.controller.ts        # /auth/nonce, /auth/login, /auth/refresh, /auth/logout
    auth.service.ts           # Business logic for authentication
    strategies/
      jwt.strategy.ts         # Passport JWT strategy for CipherBox tokens
    guards/
      jwt-auth.guard.ts       # Guard using JWT strategy
    dto/
      login.dto.ts            # Login request DTOs (JWT and SIWE variants)
      token.dto.ts            # Token response DTOs
    entities/
      user.entity.ts          # User TypeORM entity
      refresh-token.entity.ts # Refresh token TypeORM entity
      auth-nonce.entity.ts    # SIWE nonce TypeORM entity
    services/
      web3auth-verifier.service.ts  # Web3Auth JWT verification
      token.service.ts              # Access/refresh token management
```

**Frontend (apps/web/src):**

```
src/
  lib/
    web3auth/
      config.ts               # Web3Auth configuration
      provider.tsx            # Web3AuthProvider wrapper
      hooks.ts                # Custom auth hooks re-exports
    api/
      client.ts               # Axios instance with interceptors
      auth.ts                 # Auth API calls
  stores/
    auth.store.ts             # Auth state (zustand or context)
  components/
    auth/
      LoginButton.tsx         # Login modal trigger
      AuthMethodButtons.tsx   # Individual auth method buttons
      LogoutButton.tsx        # Logout handler
```

### Pattern 1: Two-Phase Authentication Flow

**What:** User authenticates with Web3Auth first (gets keypair + idToken), then authenticates with CipherBox backend (gets access/refresh tokens).

**When to use:** All authentication scenarios in CipherBox.

**Example:**

```typescript
// Source: Web3Auth Documentation + CipherBox Architecture
// Frontend: apps/web/src/lib/web3auth/hooks.ts

import { useWeb3Auth, useWeb3AuthConnect } from '@web3auth/modal/react';

export function useAuthFlow() {
  const { isConnected, provider, userInfo } = useWeb3Auth();
  const { connect, connectTo } = useWeb3AuthConnect();

  const authenticateWithBackend = async () => {
    if (!isConnected || !provider) return null;

    // 1. Get idToken from Web3Auth
    const idToken = await web3auth.authenticateUser();

    // 2. Get public key from provider
    const accounts = await provider.request({ method: 'eth_accounts' });
    const publicKey = accounts[0]; // For social logins, derive from private key

    // 3. Send to CipherBox backend
    const response = await authApi.login({ idToken, publicKey });

    return response; // { accessToken, refreshToken, teeKeys, ... }
  };

  return { connect, connectTo, authenticateWithBackend, isConnected };
}
```

### Pattern 2: Dual JWKS Endpoint Verification

**What:** Backend must use different JWKS endpoints based on whether user logged in via social login or external wallet.

**When to use:** POST /auth/login endpoint when verifying Web3Auth JWT.

**Example:**

```typescript
// Source: Web3Auth Server-Side Verification Documentation
// Backend: apps/api/src/auth/services/web3auth-verifier.service.ts

import * as jose from 'jose';

type LoginType = 'social' | 'external_wallet';

const JWKS_ENDPOINTS = {
  social: 'https://api-auth.web3auth.io/jwks',
  external_wallet: 'https://authjs.web3auth.io/jwks',
} as const;

@Injectable()
export class Web3AuthVerifierService {
  async verifyIdToken(idToken: string, expectedPublicKeyOrAddress: string, loginType: LoginType) {
    const jwksUrl = JWKS_ENDPOINTS[loginType];
    const jwks = jose.createRemoteJWKSet(new URL(jwksUrl));

    const { payload } = await jose.jwtVerify(idToken, jwks, {
      algorithms: ['ES256'],
    });

    // Verify wallet/public key matches
    if (loginType === 'social') {
      const walletKey = payload.wallets?.find(
        (w: any) => w.type === 'web3auth_app_key' && w.curve === 'secp256k1'
      );
      if (walletKey?.public_key !== expectedPublicKeyOrAddress) {
        throw new UnauthorizedException('Public key mismatch');
      }
    } else {
      const wallet = payload.wallets?.find((w: any) => w.type === 'ethereum');
      if (wallet?.address.toLowerCase() !== expectedPublicKeyOrAddress.toLowerCase()) {
        throw new UnauthorizedException('Wallet address mismatch');
      }
    }

    return payload;
  }
}
```

### Pattern 3: Silent Token Refresh with Axios Interceptors

**What:** Automatically refresh access tokens when they expire, queue failed requests and retry.

**When to use:** All authenticated API calls from frontend.

**Example:**

```typescript
// Source: Community best practices
// Frontend: apps/web/src/lib/api/client.ts

import axios from 'axios';

let isRefreshing = false;
let failedQueue: Array<{ resolve: Function; reject: Function }> = [];

const processQueue = (error: Error | null, token: string | null) => {
  failedQueue.forEach(({ resolve, reject }) => {
    if (error) reject(error);
    else resolve(token);
  });
  failedQueue = [];
};

export const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_URL,
  withCredentials: true, // For HTTP-only cookies
});

apiClient.interceptors.request.use((config) => {
  const accessToken = authStore.getState().accessToken;
  if (accessToken) {
    config.headers.Authorization = `Bearer ${accessToken}`;
  }
  return config;
});

apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    if (error.response?.status === 401 && !originalRequest._retry) {
      if (isRefreshing) {
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        }).then((token) => {
          originalRequest.headers.Authorization = `Bearer ${token}`;
          return apiClient(originalRequest);
        });
      }

      originalRequest._retry = true;
      isRefreshing = true;

      try {
        const { accessToken } = await authApi.refresh();
        authStore.getState().setAccessToken(accessToken);
        processQueue(null, accessToken);
        originalRequest.headers.Authorization = `Bearer ${accessToken}`;
        return apiClient(originalRequest);
      } catch (refreshError) {
        processQueue(refreshError as Error, null);
        authStore.getState().logout();
        throw refreshError;
      } finally {
        isRefreshing = false;
      }
    }

    throw error;
  }
);
```

### Pattern 4: Refresh Token Rotation with Hashing

**What:** Store refresh tokens as hashes, rotate on each use, invalidate old tokens.

**When to use:** POST /auth/refresh endpoint.

**Example:**

```typescript
// Source: NestJS authentication best practices
// Backend: apps/api/src/auth/services/token.service.ts

import * as argon2 from 'argon2';
import { randomBytes } from 'crypto';

@Injectable()
export class TokenService {
  constructor(
    private jwtService: JwtService,
    @InjectRepository(RefreshToken)
    private refreshTokenRepo: Repository<RefreshToken>
  ) {}

  async createTokens(userId: string) {
    const accessToken = this.jwtService.sign({ sub: userId }, { expiresIn: '15m' });

    const refreshToken = randomBytes(32).toString('hex');
    const tokenHash = await argon2.hash(refreshToken);

    await this.refreshTokenRepo.save({
      userId,
      tokenHash,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
    });

    return { accessToken, refreshToken };
  }

  async rotateRefreshToken(oldRefreshToken: string, userId: string) {
    const tokens = await this.refreshTokenRepo.find({
      where: { userId, revokedAt: IsNull() },
    });

    // Find matching token
    let validToken: RefreshToken | null = null;
    for (const token of tokens) {
      if (await argon2.verify(token.tokenHash, oldRefreshToken)) {
        validToken = token;
        break;
      }
    }

    if (!validToken || validToken.expiresAt < new Date()) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    // Revoke old token
    validToken.revokedAt = new Date();
    await this.refreshTokenRepo.save(validToken);

    // Create new tokens
    return this.createTokens(userId);
  }
}
```

### Anti-Patterns to Avoid

- **Storing access tokens in localStorage/sessionStorage:** XSS vulnerability. Store in memory only.
- **Single JWKS endpoint for all login types:** Web3Auth uses different endpoints for social vs external wallets.
- **Not rotating refresh tokens:** Reuse allows stolen tokens to work indefinitely.
- **Logging sensitive tokens or keys:** Never log tokens, private keys, or refresh tokens.
- **Synchronous token refresh without queuing:** Multiple 401s cause race conditions and multiple refresh calls.

## Don't Hand-Roll

Problems that look simple but have existing solutions:

| Problem                | Don't Build                    | Use Instead                           | Why                                                     |
| ---------------------- | ------------------------------ | ------------------------------------- | ------------------------------------------------------- |
| JWT verification       | Custom parsing/signature check | jose library                          | Handles JWK sets, key rotation, algorithm verification  |
| Password/token hashing | Custom hash function           | argon2                                | Memory-hard, GPU-resistant, industry standard           |
| Auth guards in NestJS  | Custom middleware              | @nestjs/passport + passport-jwt       | Standard patterns, well-tested, extensible              |
| Token refresh flow     | Ad-hoc retry logic             | Axios interceptors with queue pattern | Handles concurrent requests, prevents race conditions   |
| Web3Auth modal UI      | Custom login UI                | @web3auth/modal                       | Handles OAuth flows, wallet connections, key derivation |

**Key insight:** Authentication has too many edge cases (token expiry, race conditions, key rotation, different wallet types) to safely hand-roll. The Web3Auth SDK alone handles OAuth flows for Google/Apple/GitHub, magic link emails, wallet signatures, and key derivation - each would take weeks to implement correctly.

## Common Pitfalls

### Pitfall 1: Using Wrong JWKS Endpoint for External Wallets

**What goes wrong:** JWT verification fails with "signature verification failed" or "key not found".
**Why it happens:** Social logins use `https://api-auth.web3auth.io/jwks` but external wallets (MetaMask, WalletConnect) use `https://authjs.web3auth.io/jwks`.
**How to avoid:** Detect login type from request (e.g., flag in login DTO) and select appropriate endpoint. The JWT payload structure also differs - social logins have `public_key` while external wallets have `address`.
**Warning signs:** Intermittent auth failures only for wallet users.

### Pitfall 2: Refresh Token Race Conditions

**What goes wrong:** Multiple API calls fail simultaneously, each triggers token refresh, causing multiple refresh requests and token invalidation.
**Why it happens:** No coordination between concurrent 401 responses.
**How to avoid:** Use request queuing pattern - first 401 triggers refresh, subsequent 401s wait for that refresh to complete, then all retry with new token.
**Warning signs:** Users getting logged out randomly, "invalid refresh token" errors in production.

### Pitfall 3: Storing Access Tokens in localStorage

**What goes wrong:** XSS attack can steal tokens.
**Why it happens:** Developers want persistence across page refreshes.
**How to avoid:** Store access token in memory (React state/store), use HTTP-only cookie for refresh token. On page load, call /auth/refresh to get new access token.
**Warning signs:** Security audit findings, tokens visible in DevTools.

### Pitfall 4: Not Handling Group Connections

**What goes wrong:** Same user logging in with Google vs Email gets different keypairs and different vaults.
**Why it happens:** Web3Auth generates different keys per auth method unless grouped.
**How to avoid:** Configure `groupedAuthConnectionId` in Web3Auth modal config to ensure all auth methods derive the same keypair.
**Warning signs:** Users "losing" their vault when switching login methods.

### Pitfall 5: Exposing Private Key Outside Memory

**What goes wrong:** Private key written to storage, logged, or transmitted.
**Why it happens:** Debugging, confusion about what to send to backend.
**How to avoid:** Only send `publicKey` and `idToken` to backend. Private key stays in Web3Auth provider, used only for client-side operations.
**Warning signs:** Private keys appearing in network tab, logs, or storage.

## Code Examples

Verified patterns from official sources and project architecture:

### Web3Auth Provider Setup

```typescript
// Source: Web3Auth React SDK Documentation
// Frontend: apps/web/src/lib/web3auth/config.ts

import { WEB3AUTH_NETWORK, type Web3AuthOptions } from '@web3auth/modal';
import { WALLET_CONNECTORS, AUTH_CONNECTION } from '@web3auth/modal';

export const web3AuthOptions: Web3AuthOptions = {
  clientId: import.meta.env.VITE_WEB3AUTH_CLIENT_ID,
  web3AuthNetwork: WEB3AUTH_NETWORK.SAPPHIRE_MAINNET,
  modalConfig: {
    connectors: {
      [WALLET_CONNECTORS.AUTH]: {
        label: 'auth',
        loginMethods: {
          google: {
            name: 'Google',
            authConnectionId: 'w3a-google',
            groupedAuthConnectionId: 'cipherbox-aggregate', // CRITICAL: Group connection
          },
          email_passwordless: {
            name: 'Email',
            authConnectionId: 'w3a-email-passwordless',
            groupedAuthConnectionId: 'cipherbox-aggregate', // Same group
          },
          apple: {
            name: 'Apple',
            authConnectionId: 'w3a-apple',
            groupedAuthConnectionId: 'cipherbox-aggregate',
          },
          github: {
            name: 'GitHub',
            authConnectionId: 'w3a-github',
            groupedAuthConnectionId: 'cipherbox-aggregate',
          },
        },
        showOnModal: true,
      },
      [WALLET_CONNECTORS.WALLET_CONNECT_V2]: {
        label: 'WalletConnect',
        showOnModal: true,
      },
      [WALLET_CONNECTORS.METAMASK]: {
        label: 'MetaMask',
        showOnModal: true,
      },
    },
  },
};
```

### Auth Module Setup (NestJS)

```typescript
// Source: NestJS Authentication Documentation
// Backend: apps/api/src/auth/auth.module.ts

import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';

import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtStrategy } from './strategies/jwt.strategy';
import { Web3AuthVerifierService } from './services/web3auth-verifier.service';
import { TokenService } from './services/token.service';
import { User } from './entities/user.entity';
import { RefreshToken } from './entities/refresh-token.entity';
import { AuthNonce } from './entities/auth-nonce.entity';

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_SECRET'),
        signOptions: { expiresIn: '15m' },
      }),
      inject: [ConfigService],
    }),
    TypeOrmModule.forFeature([User, RefreshToken, AuthNonce]),
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy, Web3AuthVerifierService, TokenService],
  exports: [AuthService, JwtModule],
})
export class AuthModule {}
```

### JWT Strategy for CipherBox Tokens

```typescript
// Source: NestJS Passport Documentation
// Backend: apps/api/src/auth/strategies/jwt.strategy.ts

import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../entities/user.entity';

interface JwtPayload {
  sub: string; // User ID (UUID)
  publicKey: string;
  iat: number;
  exp: number;
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    configService: ConfigService,
    @InjectRepository(User)
    private userRepository: Repository<User>
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('JWT_SECRET'),
    });
  }

  async validate(payload: JwtPayload): Promise<User> {
    const user = await this.userRepository.findOne({
      where: { id: payload.sub },
    });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    return user;
  }
}
```

### Login Endpoint Implementation

```typescript
// Source: CipherBox API Specification + Web3Auth Documentation
// Backend: apps/api/src/auth/auth.controller.ts

import { Controller, Post, Body, HttpCode, HttpStatus } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { LoginDto, LoginResponseDto } from './dto';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Authenticate user with Web3Auth ID token' })
  @ApiResponse({ status: 200, type: LoginResponseDto })
  async login(@Body() loginDto: LoginDto): Promise<LoginResponseDto> {
    return this.authService.login(loginDto);
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Refresh access token' })
  async refresh(@Body() body: { refreshToken: string }) {
    return this.authService.refreshTokens(body.refreshToken);
  }
}
```

### Auth State Store (Frontend)

```typescript
// Source: Zustand + React Query best practices
// Frontend: apps/web/src/stores/auth.store.ts

import { create } from 'zustand';

type AuthState = {
  accessToken: string | null;
  isAuthenticated: boolean;
  teeKeys: {
    currentEpoch: number;
    currentPublicKey: string;
    previousEpoch: number | null;
    previousPublicKey: string | null;
  } | null;

  setAccessToken: (token: string) => void;
  setTeeKeys: (keys: AuthState['teeKeys']) => void;
  logout: () => void;
};

export const useAuthStore = create<AuthState>((set) => ({
  accessToken: null,
  isAuthenticated: false,
  teeKeys: null,

  setAccessToken: (token) => set({ accessToken: token, isAuthenticated: true }),
  setTeeKeys: (keys) => set({ teeKeys: keys }),
  logout: () => set({ accessToken: null, isAuthenticated: false, teeKeys: null }),
}));
```

## State of the Art

| Old Approach        | Current Approach           | When Changed           | Impact                                     |
| ------------------- | -------------------------- | ---------------------- | ------------------------------------------ |
| @web3auth/web3auth  | @web3auth/modal v10        | 2024                   | New modal SDK with React hooks built-in    |
| Aggregate verifiers | Group connections          | v10 migration          | Same concept, new terminology in dashboard |
| jsonwebtoken        | jose                       | 2023+                  | jose works in browser, better JWKS support |
| bcrypt for tokens   | argon2                     | Best practice 2024+    | argon2 is memory-hard, better for servers  |
| localStorage tokens | Memory + HTTP-only cookies | Security best practice | Prevents XSS token theft                   |

**Deprecated/outdated:**

- `@web3auth/modal-react-hooks`: Now part of `@web3auth/modal/react` (subpath export)
- `https://api.openlogin.com/jwks`: Legacy JWKS endpoint, use `https://api-auth.web3auth.io/jwks`
- `web3auth.getUserInfo().idToken`: Use `web3auth.authenticateUser()` to get current token

## Open Questions

Things that couldn't be fully resolved:

1. **Web3Auth Dashboard Configuration for Group Connections**
   - What we know: Group connections require `groupedAuthConnectionId` configuration
   - What's unclear: Exact dashboard setup steps for CipherBox project, requires Growth Plan access
   - Recommendation: Set up during implementation, verify group ID matches between dashboard and code

2. **Token Storage: HTTP-only Cookie vs Memory**
   - What we know: CONTEXT.md marks this as "Claude's discretion"
   - Recommendation: Use HTTP-only cookie for refresh token (7 days), memory for access token (15 min). This balances security (no XSS access to refresh token) with UX (session persists across page refreshes via /auth/refresh call)

3. **"Remember Me" Session Extension**
   - What we know: CONTEXT.md says explicit opt-in extends session duration
   - What's unclear: How much to extend (30 days? 90 days?)
   - Recommendation: Extend refresh token to 30 days when "Remember Me" is checked

## Sources

### Primary (HIGH confidence)

- [Web3Auth React SDK Documentation](https://web3auth.io/docs/sdk/web/react) - Modal configuration, hooks
- [Web3Auth Server-Side Verification](https://web3auth.io/docs/features/server-side-verification) - JWT verification, JWKS endpoints
- [NestJS Authentication Documentation](https://docs.nestjs.com/security/authentication) - Passport, JWT guards
- [@web3auth/modal npm](https://www.npmjs.com/package/@web3auth/modal) - Version 10.10.0 confirmed
- [jose npm](https://www.npmjs.com/package/jose) - JWT verification library

### Secondary (MEDIUM confidence)

- [Web3Auth Identity Token Structure](https://web3auth.io/docs/authentication/id-token) - JWT payload structure, wallets array
- [Web3Auth Group Connections](https://web3auth.io/docs/authentication/group-connections) - Same keypair across auth methods
- [NestJS JWT with Refresh Tokens Guide](https://dev.to/zenstok/how-to-implement-refresh-tokens-with-token-rotation-in-nestjs-1deg) - Token rotation patterns
- [TanStack Query Auth Token Refresh](https://elazizi.com/posts/react-query-auth-token-refresh/) - React Query + Axios patterns

### Tertiary (LOW confidence)

- Community discussions on external wallet JWKS differences - Needs verification during implementation
- argon2 vs bcrypt recommendations - Generally accepted but verify with security team if needed

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH - Official documentation and npm verified
- Architecture: HIGH - Based on Web3Auth docs and NestJS standards
- Pitfalls: HIGH - Well-documented issues with JWKS endpoints, token refresh

**Research date:** 2026-01-20
**Valid until:** 2026-02-20 (30 days - Web3Auth SDK evolves but major patterns stable)
