import { SetMetadata } from '@nestjs/common';

/**
 * The scopes a restricted token may hold. A token carrying no `scope` claim has
 * full account authority; a scoped one is a capability, not a session.
 */
export type TokenScope = 'device-approval';

export const ALLOWED_SCOPES_KEY = 'cipherbox:allowed-scopes';

/**
 * Mark the routes a scoped token may reach. Absence is a refusal, not a
 * permission: `JwtAuthGuard` rejects a scoped token on every undecorated route,
 * so a new route is closed to scoped tokens the moment it lands.
 */
export const AllowScope = (...scopes: TokenScope[]) => SetMetadata(ALLOWED_SCOPES_KEY, scopes);
