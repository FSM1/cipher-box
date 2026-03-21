/**
 * Health check hook wrapping the @cipherbox/api-client generated function
 * with @tanstack/react-query for auto-refetching and caching.
 *
 * Replaces the orval-generated useHealthControllerCheck react-query hook.
 */
import { useQuery } from '@tanstack/react-query';
import type { UseQueryOptions } from '@tanstack/react-query';
import { healthControllerCheck } from '@cipherbox/api-client';
import type { HealthControllerCheck200 } from '@cipherbox/api-client';

type HealthData = Awaited<ReturnType<typeof healthControllerCheck>>;

export function useHealthCheck(options?: {
  query?: Partial<UseQueryOptions<HealthData, Error, HealthControllerCheck200>>;
}) {
  const { query: queryOptions } = options ?? {};

  return useQuery<HealthData, Error, HealthControllerCheck200>({
    queryKey: ['health'],
    queryFn: () => healthControllerCheck(),
    ...queryOptions,
  });
}
