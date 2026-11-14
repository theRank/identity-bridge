# syntax=docker/dockerfile:1.27@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# The Dockerfile frontend, docker/dockerfile:1.27 (1.27.1), pinned by digest like the base image.

# Both stages use node:24-slim (Node 24 LTS on Debian bookworm), pinned by digest; dependabot proposes new digests.

# The bundle is plain JavaScript, so it is built once on the builder's own platform for every target, and an image
# for another architecture needs no emulation
FROM --platform=$BUILDPLATFORM node:24-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54 AS build
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages/client/package.json packages/client/
COPY packages/server/package.json packages/server/
# A registry mirror for npm ci, such as one closer to the builder; left empty, npm uses its own default
ARG NPM_CONFIG_REGISTRY=
# No install script is needed: esbuild ships its binary as a platform package
RUN --mount=type=cache,target=/root/.npm npm ci --ignore-scripts --no-audit --no-fund
COPY tsconfig.json ./
COPY scripts/build-node.ts scripts/
COPY src ./src
RUN npm run build:node

# Node and the bundle, which has jose built in and its licence in its banner, so there is nothing to install and
# no source; LICENSE is the bridge's own
FROM node:24-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54
ARG VERSION=dev
# The commit the image is built from, passed by the workflows
ARG REVISION=
LABEL org.opencontainers.image.source="https://github.com/theRank/identity-bridge" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$REVISION" \
      org.opencontainers.image.licenses="Apache-2.0"
WORKDIR /app
COPY --from=build /app/dist/node/server.mjs ./
COPY LICENSE ./
# The image's node user, by number, so that an orchestrator's runAsNonRoot can verify it is not root
USER 1000:1000
ENV PORT=8080
EXPOSE 8080
# The image has no curl; Node's fetch does the check, and anything but 200, including the 503 of a runtime that
# failed to load, is unhealthy
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --start-interval=1s \
    CMD ["node", "-e", "fetch(`http://127.0.0.1:${process.env.PORT || 8080}/healthz`).then((r) => process.exit(r.status === 200 ? 0 : 1), () => process.exit(1))"]
CMD ["node", "server.mjs"]
