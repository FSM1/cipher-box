FROM node:20-alpine

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --production

COPY dist/ ./dist/

ENV NODE_ENV=production
ENV TEE_MODE=cvm
ENV PORT=3001

EXPOSE 3001

CMD ["node", "dist/index.js"]
