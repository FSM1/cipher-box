# This tool is not a pnpm workspace member: it carries its own npm lockfile and
# builds with npm, the same recipe .github/actions/mock-ipns-routing runs.
FROM node:22-alpine

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
# The build needs the dev tree; the runtime needs only fastify and pino-pretty.
RUN npm run build && npm prune --omit=dev

ENV HOST=0.0.0.0 \
    PORT=3001 \
    NODE_ENV=production

USER node

EXPOSE 3001

CMD ["node", "dist/index.js"]
