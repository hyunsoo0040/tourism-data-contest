# syntax=docker/dockerfile:1.7
FROM node:24.18.0-slim@sha256:d45d78e7929b46875bbd4e29bea672d5bc48186c6c3588306521c815e78352d6 AS dependencies
ENV PNPM_HOME=/pnpm \
    PATH=/pnpm:$PATH \
    CI=true
RUN corepack enable && corepack prepare pnpm@11.15.1 --activate
WORKDIR /app/web
COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml ./
RUN --mount=type=cache,target=/pnpm/store \
    pnpm install --frozen-lockfile --ignore-scripts

FROM dependencies AS builder
WORKDIR /app
COPY web /app/web
COPY contracts/questionnaire-v1.json contracts/questionnaire-v2.json /app/contracts/
WORKDIR /app/web
ENV NEXT_TELEMETRY_DISABLED=1 \
    ITDA_BACKEND_ORIGIN=http://backend:8000
RUN pnpm build

FROM node:24.18.0-slim@sha256:d45d78e7929b46875bbd4e29bea672d5bc48186c6c3588306521c815e78352d6 AS runtime
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    HOSTNAME=0.0.0.0 \
    PORT=3000
WORKDIR /app
RUN groupadd --gid 10001 itda && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin itda
COPY --from=builder --chown=10001:10001 /app/web/.next/standalone ./
COPY --from=builder --chown=10001:10001 /app/web/.next/static ./web/.next/static
COPY --from=builder --chown=10001:10001 /app/web/public ./web/public
USER 10001:10001
EXPOSE 3000
CMD ["node", "web/server.js"]
