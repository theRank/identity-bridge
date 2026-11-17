# syntax=docker/dockerfile:1.27@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e

# Build plain JavaScript on the native platform; cross-platform images need no emulation.
FROM --platform=$BUILDPLATFORM node:24-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54 AS build
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages/client/package.json packages/client/
COPY packages/server/package.json packages/server/
# Optional npm registry mirror.
ARG NPM_CONFIG_REGISTRY=
# No install script is needed: esbuild ships its binary as a platform package
RUN --mount=type=cache,target=/root/.npm npm ci --ignore-scripts --no-audit --no-fund
COPY tsconfig.json ./
COPY scripts/build-node.ts scripts/licence.ts scripts/
COPY src ./src
RUN npm run build:node

FROM node:24-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54
ARG VERSION=dev
ARG REVISION=
LABEL org.opencontainers.image.source="https://github.com/theRank/identity-bridge" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$REVISION" \
      org.opencontainers.image.licenses="Apache-2.0"
WORKDIR /app
COPY --from=build /app/dist/node/server.mjs ./
COPY LICENSE ./
# Numeric uid lets orchestrators enforce runAsNonRoot.
USER 1000:1000
ENV PORT=8080
EXPOSE 8080
# Use Node's fetch because the image has no curl.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --start-interval=1s \
    CMD ["node", "-e", "fetch(`http://127.0.0.1:${process.env.PORT || 8080}/healthz`).then((r) => process.exit(r.status === 200 ? 0 : 1), () => process.exit(1))"]
CMD ["node", "server.mjs"]
