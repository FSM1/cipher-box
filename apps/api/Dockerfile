# CipherBox API - Multi-stage Docker build
# Build from repo root: docker build -f apps/api/Dockerfile -t cipherbox-api .

# Stage 1: Install production dependencies
FROM node:22-alpine AS deps
RUN corepack enable && corepack prepare pnpm@10 --activate
WORKDIR /app
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY apps/api/package.json apps/api/
RUN pnpm install --frozen-lockfile --filter @cipherbox/api...

# Stage 2: Build TypeScript
FROM deps AS build
COPY apps/api/ apps/api/
COPY tsconfig.base.json ./
RUN pnpm --filter @cipherbox/api build

# Stage 3: Production runtime
FROM node:22-alpine AS production
RUN addgroup -g 1001 -S appgroup && adduser -S appuser -u 1001 -G appgroup
WORKDIR /app

# Copy compiled output
COPY --from=build /app/apps/api/dist ./dist

# Copy node_modules from both root and workspace (pnpm hoists some deps to root)
COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/apps/api/node_modules ./apps/api/node_modules

# Copy package.json for module resolution
COPY --from=deps /app/apps/api/package.json ./package.json

ENV NODE_ENV=production
ENV PORT=3000

USER appuser
EXPOSE 3000
CMD ["node", "dist/main.js"]
