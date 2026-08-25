import { ConfigService } from '@nestjs/config';
import { positiveIntConfig } from '../../common/config-int';

/** Short-lived by doctrine (blueprint/api.md, Identity and auth). */
const DEFAULT_ACCESS_TTL_SECONDS = 900;

/** The access token's lifetime, which the gateway pseudonym shares. */
export function resolveAccessTtlSeconds(configService: ConfigService): number {
  return positiveIntConfig(
    configService.get('ACCESS_TOKEN_TTL_SECONDS'),
    DEFAULT_ACCESS_TTL_SECONDS
  );
}
