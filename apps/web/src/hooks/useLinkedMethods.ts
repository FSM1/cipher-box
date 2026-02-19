import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { authApi, AuthMethod } from '../lib/api/auth';

type LinkPayload = {
  idToken: string;
  loginType: 'google' | 'email' | 'wallet';
  walletAddress?: string;
  siweMessage?: string;
  siweSignature?: string;
};

export function useLinkedMethods() {
  const queryClient = useQueryClient();

  const {
    data: methods = [],
    isLoading,
    error,
  } = useQuery<AuthMethod[], Error>({
    queryKey: ['auth-methods'],
    queryFn: authApi.getMethods,
  });

  const linkMutation = useMutation({
    mutationFn: (payload: LinkPayload) => authApi.linkMethod(payload),
    onSuccess: (updatedMethods) => {
      // Update cache with the returned list
      queryClient.setQueryData(['auth-methods'], updatedMethods);
    },
  });

  const unlinkMutation = useMutation({
    mutationFn: authApi.unlinkMethod,
    onSuccess: () => {
      // Invalidate to refetch the updated list
      queryClient.invalidateQueries({ queryKey: ['auth-methods'] });
    },
  });

  return {
    methods,
    isLoading,
    error,
    linkMethod: linkMutation.mutateAsync,
    unlinkMethod: unlinkMutation.mutateAsync,
    isLinking: linkMutation.isPending,
    isUnlinking: unlinkMutation.isPending,
    linkError: linkMutation.error,
    unlinkError: unlinkMutation.error,
    resetLinkError: linkMutation.reset,
  };
}
