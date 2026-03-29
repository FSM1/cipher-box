# CipherBox TEE Worker - Multi-stage Docker build
# Build from repo root: docker build -f apps/tee-worker/Dockerfile -t cipherbox-tee-worker .

# Stage 1: Install dependencies and build TypeScript
FROM node:20-alpine AS build
RUN corepack enable && corepack prepare pnpm@10 --activate
WORKDIR /app
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY apps/tee-worker/package.json apps/tee-worker/
COPY packages/crypto/package.json packages/crypto/
COPY packages/core/package.json packages/core/
COPY packages/sdk-core/package.json packages/sdk-core/
RUN pnpm install --frozen-lockfile --filter cipherbox-tee-worker...
COPY apps/tee-worker/ apps/tee-worker/
COPY packages/crypto/ packages/crypto/
COPY packages/core/ packages/core/
COPY packages/sdk-core/ packages/sdk-core/
COPY tsconfig.base.json ./
RUN pnpm --filter @cipherbox/crypto build && pnpm --filter @cipherbox/core build && pnpm --filter @cipherbox/sdk-core build
RUN pnpm --filter cipherbox-tee-worker build

# Create standalone deployment (flat node_modules, no symlinks)
RUN pnpm --filter cipherbox-tee-worker deploy /deploy --prod --legacy

# Stage 2: Production runtime
FROM node:20-alpine
RUN addgroup -g 1001 -S appgroup && adduser -S appuser -u 1001 -G appgroup
WORKDIR /app
COPY --from=build /deploy/node_modules ./node_modules
COPY --from=build /app/apps/tee-worker/dist ./dist
COPY --from=build /deploy/package.json ./package.json

ENV NODE_ENV=production
ENV PORT=3001
EXPOSE 3001
USER appuser
CMD ["node", "dist/index.js"]
