# CipherBox API. Build from the repo root:
#   docker build -f apps/api/Dockerfile -t cipherbox-api .
# The API is the only workspace project in the image: it links no package and
# no crate, so the build graph is the API alone.
FROM node:22-alpine AS build
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0
RUN corepack enable && corepack prepare pnpm@10.33.0 --activate
WORKDIR /app
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json tsconfig.base.json ./
COPY apps/api/package.json apps/api/
RUN pnpm install --frozen-lockfile --filter @cipherbox/api
COPY apps/api/ apps/api/
RUN pnpm --filter @cipherbox/api build
# A flat, symlink-free node_modules for the runtime stage.
RUN pnpm --filter @cipherbox/api deploy /deploy --prod --legacy

FROM node:22-alpine AS production
RUN addgroup -g 1001 -S appgroup && adduser -S appuser -u 1001 -G appgroup
WORKDIR /app
COPY --from=build /deploy/node_modules ./node_modules
COPY --from=build /deploy/package.json ./package.json
COPY --from=build /app/apps/api/dist ./dist
ENV NODE_ENV=production
ENV PORT=3000
USER appuser
EXPOSE 3000
CMD ["node", "dist/main.js"]
