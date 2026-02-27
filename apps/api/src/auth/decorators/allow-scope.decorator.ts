import { SetMetadata } from '@nestjs/common';

/**
 * Marks a route or controller as accepting scoped (temp auth) tokens.
 *
 * By default, JwtAuthGuard rejects scoped tokens on all routes.
 * Apply this decorator to routes that should be accessible with
 * restricted-scope tokens (e.g., device-approval endpoints for
 * REQUIRED_SHARE temp auth).
 *
 * @example
 * ```ts
 * @AllowScope('device-approval')
 * @Controller('device-approval')
 * export class DeviceApprovalController {}
 * ```
 */
export const AllowScope = (...scopes: string[]) => SetMetadata('allowedScopes', scopes);
