# Deploying on Node

The bridge as an HTTP server on Node 24 or later, in a container or as a plain process. In mainland China this
suits a deployer who already runs the host of a self-hosted Casdoor: the bridge runs beside it, behind the same
reverse proxy. [Choosing a runtime](../README.md#choosing-a-runtime) compares the options.

## Artifacts

Each release provides the same server three ways. Pin a release version, never `latest`.

| Artifact | What it is |
|---|---|
| `server.mjs` | A single file with its one dependency, jose, built in, attached to the [GitHub release](https://github.com/theRank/identity-bridge/releases) with its SHA-256. It runs with plain `node`, such as on the official `node:24-slim` image |
| `Dockerfile` | The repository's image definition: `node:24-slim`, pinned by digest, with only `server.mjs` and `LICENSE`, running as the base image's `node` user, uid 1000 ([Node.js images][node-image-user]) |
| `ghcr.io/therank/identity-bridge` | That image, built for `linux/amd64` and `linux/arm64`, tagged `X.Y.Z` for every release, plus `X.Y` and `latest` for the highest release |

Pulling from `ghcr.io` can be slow or fail inside mainland China. There, mirror the image into a registry in
the mainland, such as Alibaba Cloud Container Registry, or run the bundle on a `node:24-slim` image that a
mainland registry mirrors.

GitHub publishes a package as private, and a package never takes on its repository's visibility, so the
package is made public by hand in its settings ([GitHub][gh-visibility]). If a pull asks for credentials, build
the image from the `Dockerfile` or use the bundle.

### The bundle

```sh
VERSION=v1.0.0
curl -fsSLO "https://github.com/theRank/identity-bridge/releases/download/$VERSION/server.mjs"
curl -fsSLO "https://github.com/theRank/identity-bridge/releases/download/$VERSION/server.mjs.sha256"
sha256sum -c server.mjs.sha256   # on macOS: shasum -a 256 -c server.mjs.sha256
node server.mjs
```

The bundle needs nothing installed beside it, and has the licences of the bridge and of jose in its first
lines.

### Building the image

```sh
git clone --depth 1 --branch v1.0.0 https://github.com/theRank/identity-bridge.git
docker build --build-arg VERSION=1.0.0 --tag identity-bridge:1.0.0 identity-bridge
```

Build arguments: `VERSION` and `REVISION` fill the image's OCI labels, and `NPM_CONFIG_REGISTRY` points the
build stage's `npm ci` at a registry mirror.

## Configuration and secrets

The server reads its environment once, at start:

| Variable | Default | Meaning |
|---|---|---|
| `BRIDGE_CONFIG` | | The [configuration document](configuration.md#the-configuration-document) |
| `SIGNING_KEYS` | | The [signing keys](configuration.md#signing-keys) |
| `WEBHOOK_SECRET_<SOURCE>` | | One per [webhook source](configuration.md#webhook-secrets) |
| `PORT` | `8080` | The port to listen on, over plain HTTP |
| `HOST` | `0.0.0.0` | The address to listen on |

- `HOST` must include the loopback address, as `0.0.0.0` and `::` do, because the image's health check probes
  `127.0.0.1`.
- A change takes effect on restart: the runtime is loaded once per process.
- Webhook secrets must not start or end with whitespace. A secret file that ends with a newline fails the load,
  with the reason `webhook secret for source <id> has surrounding whitespace`.

Pass `SIGNING_KEYS` and the webhook secrets from your orchestrator's secrets or from files at run time. Never
bake them into an image. With `docker run`, an env file holds one `NAME=value` per line
([Docker][docker-env-file]), each value taken as written, quotes included ([source][docker-kvfile]), so a JSON
value needs no escaping. Compose's own `.env` files treat quotes differently ([Compose][compose-env-file]); use
the secrets below there instead.

```sh
docker run --detach --name identity-bridge --publish 127.0.0.1:8080:8080 \
    --env-file bridge.env ghcr.io/therank/identity-bridge:1.0.0
```

With Docker Compose secrets, which arrive as files, a shell reads them into the environment; `$(cat ...)` also
drops a trailing newline:

```yaml
services:
  identity-bridge:
    image: ghcr.io/therank/identity-bridge:1.0.0
    command: ["sh", "-c", "BRIDGE_CONFIG=\"$$(cat /run/secrets/bridge_config)\" SIGNING_KEYS=\"$$(cat /run/secrets/signing_keys)\" WEBHOOK_SECRET_CASDOOR_ACME=\"$$(cat /run/secrets/webhook_secret_casdoor_acme)\" exec node server.mjs"]
    ports: ["127.0.0.1:8080:8080"]
    stop_grace_period: 10s
    restart: unless-stopped
    secrets: [bridge_config, signing_keys, webhook_secret_casdoor_acme]
secrets:
  bridge_config:
    file: ./bridge-config.json
  signing_keys:
    file: ./signing-keys.json
  webhook_secret_casdoor_acme:
    file: ./webhook-secret-casdoor-acme
```

On Kubernetes, give each variable from a Secret with `env[].valueFrom.secretKeyRef`.

## Beside Casdoor

Run the bridge on the same host as Casdoor, behind the same reverse proxy, on a host name of its own, such as
`id.cn.acme.example`, with TLS at the proxy:

```nginx
server {
    listen 443 ssl;
    server_name id.cn.acme.example;
    ssl_certificate     /etc/ssl/id.cn.acme.example.pem;
    ssl_certificate_key /etc/ssl/id.cn.acme.example.key;

    location / {
        proxy_pass http://127.0.0.1:8080;
    }
}
```

- The host name needs ICP filing: WeChat mini programs call only HTTPS domains with ICP filing
  ([WeChat][wx-network]).
- The bridge routes by path alone and ignores `Host`.
- The server waits 10 seconds for request headers and 30 seconds for a whole request, and keeps an idle
  connection open for 65 seconds, longer than common proxies do, so the proxy closes idle connections first.

## Health check

The image's `HEALTHCHECK` fetches `http://127.0.0.1:$PORT/healthz` every 30 seconds and reports the container
unhealthy unless the answer is `200`. A deployment whose configuration or secrets fail to load keeps running in
[failure mode](api.md#failure-mode) rather than exiting, so it shows as unhealthy instead of restarting in a
loop. On Kubernetes, point the readiness probe at `/healthz`.

## Logs

The server writes JSON lines to stdout, one per request and a few events ([logs](configuration.md#logs)):

```json
{"event":"listening","host":"0.0.0.0","port":8080}
{"route":"health","status":200,"ms":3,"outcome":"ok"}
```

Collect stdout with the container runtime's logging, such as `docker logs` or the orchestrator's log driver.

A line with `status` 499 and `code` `client_closed` means the connection ended before the request was read
completely: the client went away, or the 30-second request timeout fired. The client got no answer. Only the
Node entry logs this code.

## Stopping

On `SIGTERM` or `SIGINT` the server logs `{"event":"stopping","signal":"SIGTERM"}`, stops accepting
connections, gives requests in flight up to 8 seconds, and exits: with `0`, or `1` when the deadline cut
requests off. A second signal exits at once.

Give it a stop grace period of at least 10 seconds, so the 8-second deadline, not a kill, ends a stop: Docker's
default for `docker stop` ([Docker][docker-stop]), Compose's `stop_grace_period`
([Compose][compose-stop]) and Kubernetes' `terminationGracePeriodSeconds` ([Kubernetes][k8s-termination])
all allow it unless lowered.

## Replicas

One process is enough at this load: a client exchanges about once per `tokenTtlSeconds`, plus one request per
webhook. Several replicas need nothing shared, since the bridge keeps no state; each caches IdP keys on its own.

## Smoke test

After every deploy, from a checkout of the same tag, with Node 24 or later and nothing installed:

```sh
node scripts/smoke.ts https://id.cn.acme.example acme
```

[What it checks](../README.md#smoke-test).

## Key rotation

Follow [rotating the signing key](configuration.md#rotating-the-signing-key): set the new `SIGNING_KEYS`,
restart, and run the smoke test; later drop the retired key and restart again.

## Trying it locally

With throwaway values on `*.example` hosts:

```sh
npm ci
npm run build:node
node scripts/dev-env.ts > dev.env
node --env-file=dev.env dist/node/server.mjs &
node scripts/smoke.ts http://127.0.0.1:8080 acme
```

`dev.env` also works as `docker run --env-file`. Its values are for local runs and CI only.

[gh-visibility]: https://docs.github.com/en/packages/learn-github-packages/configuring-a-packages-access-control-and-visibility#about-inheritance-of-access-permissions
[node-image-user]: https://github.com/nodejs/docker-node/blob/0a14e46ed10043bb3eb59bee8d9904a6ebea6200/docs/BestPractices.md#non-root-user
[docker-env-file]: https://docs.docker.com/reference/cli/docker/container/run/#env
[docker-kvfile]: https://github.com/docker/cli/blob/fdd4b8e5da335e1d0d83d29af5045f57280cd694/pkg/kvfile/kvfile.go#L18-L19
[compose-env-file]: https://docs.docker.com/compose/how-tos/environment-variables/variable-interpolation/#env-file-syntax
[docker-stop]: https://docs.docker.com/reference/cli/docker/container/stop/#timeout
[compose-stop]: https://docs.docker.com/reference/compose-file/services/#stop_grace_period
[k8s-termination]: https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#pod-termination-flow
[wx-network]: https://developers.weixin.qq.com/miniprogram/dev/framework/ability/network.html
