# CipherBox TEE Worker - Multi-stage Docker build
# Build: docker build -t cipherbox-tee-worker tee-worker/

# Stage 1: Install dependencies and build from source
FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY src/ ./src/
COPY tsconfig.json ./
RUN npm run build

# Stage 2: Production runtime
FROM node:20-alpine
WORKDIR /app
COPY --from=build /app/dist ./dist
COPY --from=build /app/package.json ./
COPY --from=build /app/package-lock.json ./
RUN npm ci --omit=dev

ENV NODE_ENV=production
ENV PORT=3001

EXPOSE 3001

USER node
CMD ["node", "dist/index.js"]
