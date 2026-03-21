/**
 * Health check hook wrapping the @cipherbox/api-client generated function
 * with @tanstack/react-query for auto-refetching and caching.
 */
import { useQuery } from '@tanstack/react-query';
import { healthControllerCheck } from '@cipherbox/api-client';

export function useHealthCheck() {
  return useQuery({
    queryKey: ['health'],
    queryFn: () => healthControllerCheck(),
    refetchInterval: 30_000,
    retry: 2,
    refetchOnWindowFocus: true,
  });
}
