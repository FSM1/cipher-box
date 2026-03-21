import { defineConfig } from 'orval';

export default defineConfig({
  cipherbox: {
    input: {
      target: './openapi.json',
    },
    output: {
      mode: 'tags-split',
      target: './src/generated',
      schemas: './src/models',
      client: 'axios-functions',
      override: {
        mutator: {
          path: './src/instance.ts',
          name: 'customInstance',
        },
      },
    },
  },
});
