import { defineConfig } from 'orval';

export default defineConfig({
  cipherbox: {
    input: {
      target: '../../packages/api-client/openapi.json',
    },
    output: {
      mode: 'tags-split',
      target: './src/api',
      schemas: './src/api/models',
      client: 'react-query',
      override: {
        mutator: {
          path: './src/api/custom-instance.ts',
          name: 'customInstance',
        },
        query: {
          useQuery: true,
          useMutation: true,
        },
      },
    },
  },
});
