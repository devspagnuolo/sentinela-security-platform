# syntax=docker/dockerfile:1.7
# Imagem de produção do Sentinela (linux/amd64 e linux/arm64, ex.: Oracle Cloud Ampere A1).

ARG NODE_IMAGE=node:22-bookworm-slim

FROM ${NODE_IMAGE} AS deps
WORKDIR /app
COPY package.json package-lock.json ./
COPY apps/web/package.json apps/web/
RUN npm ci --no-audit --no-fund

# Código-fonte com todas as dependências: usado no build e para comandos administrativos
# (docker compose run --rm tools npm run user:create-owner -- ...).
FROM deps AS tools
ENV NEXT_TELEMETRY_DISABLED=1
COPY . .
WORKDIR /app/apps/web

FROM tools AS build
RUN npm run build

FROM ${NODE_IMAGE} AS runtime
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0 \
    SENTINELA_MIGRATIONS_DIR=/app/apps/web/drizzle
COPY --from=build --chown=node:node /app/apps/web/.next/standalone ./
COPY --from=build --chown=node:node /app/apps/web/.next/static ./apps/web/.next/static
COPY --from=build --chown=node:node /app/apps/web/drizzle ./apps/web/drizzle
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:3000/api/health').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"]
CMD ["node", "apps/web/server.js"]
