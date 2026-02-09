# CipherBox API - Multi-stage Docker build
# Build from repo root: docker build -f apps/api/Dockerfile -t cipherbox-api .

# Stage 1: Install dependencies and build TypeScript
FROM node:22-alpine AS build
RUN corepack enable && corepack prepare pnpm@10 --activate
WORKDIR /app
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY apps/api/package.json apps/api/
COPY packages/crypto/package.json packages/crypto/
RUN pnpm install --frozen-lockfile --filter @cipherbox/api...
COPY apps/api/ apps/api/
COPY tsconfig.base.json ./
RUN pnpm --filter @cipherbox/api build

# Create standalone deployment (flat node_modules, no symlinks)
RUN pnpm --filter @cipherbox/api deploy /deploy --prod --legacy

# Stage 2: Production runtime
FROM node:22-alpine AS production
RUN addgroup -g 1001 -S appgroup && adduser -S appuser -u 1001 -G appgroup
WORKDIR /app

COPY --from=build /deploy/node_modules ./node_modules
COPY --from=build /app/apps/api/dist ./dist
COPY --from=build /deploy/package.json ./package.json

ENV NODE_ENV=production
ENV PORT=3000

USER appuser
EXPOSE 3000
CMD ["node", "dist/main.js"]
