import { ConfigService } from '@nestjs/config';
import { positiveIntConfig } from '../../common/config-int';

/** Short-lived by doctrine (blueprint/api.md, Identity and auth). */
const DEFAULT_ACCESS_TTL_SECONDS = 900;

/**
 * The access token's lifetime. The gateway pseudonym reads it from here too:
 * the two expire together by construction, not by two copies of one default
 * drifting apart.
 */
export function resolveAccessTtlSeconds(configService: ConfigService): number {
  return positiveIntConfig(
    configService.get('ACCESS_TOKEN_TTL_SECONDS'),
    DEFAULT_ACCESS_TTL_SECONDS
  );
}
