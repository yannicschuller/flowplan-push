# syntax=docker/dockerfile:1
# Flowplan push relay – multi-stage build, non-root, read-only-root-FS friendly.
ARG NODE_IMAGE=node:22.22.3-alpine3.24@sha256:e58326d0d441090181ac150dc2078d3e2cf6a0d42e809aebba3ef5880935ffdd

FROM ${NODE_IMAGE} AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm run build \
 && npm prune --omit=dev --ignore-scripts --no-audit --no-fund

FROM ${NODE_IMAGE} AS runtime
# Commit shown on the admin dashboard (CI passes the git SHA).
ARG RELAY_COMMIT=""
# OS security updates; drop npm/yarn/corepack (not needed at runtime, less attack surface).
RUN apk upgrade --no-cache \
 && rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
           /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack /opt/yarn* /usr/local/bin/yarn* \
 && mkdir -p /data && chown node:node /data && chmod 700 /data
ENV NODE_ENV=production \
    NODE_OPTIONS=--disable-warning=ExperimentalWarning \
    DATA_DIR=/data \
    PORT=8080 \
    RELAY_COMMIT=${RELAY_COMMIT}
WORKDIR /app
# Application files are owned by root and not writable by the runtime user.
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
# Logo and fonts of the admin dashboard (fonts: SIL OFL 1.1, licences beside them).
COPY assets ./assets
COPY package.json LICENSE ./
USER node
VOLUME ["/data"]
EXPOSE 8080
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/healthz').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"]
CMD ["node", "dist/src/index.js"]
