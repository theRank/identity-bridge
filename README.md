# identity-bridge

A stateless identity broker for Clerk and Casdoor. Clients exchange an identity provider's (IdP's) JWT for a
short-lived bridge access token through [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693). Product backends
verify bridge tokens against its JWKS and receive user lifecycle webhooks as signed security event tokens.

This repository provides the service and TypeScript SDKs. Clients use their IdP's sign-in flow; product
backends use the bridge's common token and event formats. Each deployer maintains its own configuration.

```text
                    1 sign in
  client ─────────────────────────────→ IdP (Clerk, Casdoor)
    │
    │ 2 POST /token with the IdP token          verified with the IdP's JWKS
    ├─────────────────────────────→ identity-bridge
    │ ←── bridge access token
    │
    │ 3 API call with the bridge token          verified with the bridge's JWKS
    └─────────────────────────────→ product backend

  IdP ── 4 user webhook ──→ identity-bridge ── 5 signed event ──→ product backend
```

## Guarantees

- **Stateless.** No database, key-value store or queue. Replicas need the same configuration and keys; each
  caches IdP public keys independently.
- **Bounded revocation.** If the IdP stops issuing tokens to a banned user or ended session, existing tokens
  allow access for at most about 32 minutes with the defaults ([calculation](docs/api.md#processing)).
- **Stable user ids.** A user's id is the UUIDv5 of the IdP's issuer and subject under a fixed namespace, or an
  id set by an administrator in the IdP. The token and the webhook paths give the same id for the same person,
  and the override keeps ids across a migration to another IdP.
- **One format.** Access tokens follow RFC 9068, signed with ES256 only, and carry the user id and, when the IdP
  verified them, the email and phone number, whatever the IdP.
- **Uniform errors, no personal data in logs.** Every rejected IdP token gets the same error; the precise reason
  goes to a log code. Logs never hold tokens, emails, phone numbers or payloads.

The bridge does not provide sign-in screens, sessions, refresh tokens, a user directory, roles or permissions,
or linking one person's accounts across IdPs, and it is not an OpenID Provider. IdPs sign users in; products
keep their own authorization, keyed by the bridge's user id.

## Documentation

- [API](docs/api.md): the endpoints, the access token, user ids, webhooks and event tokens.
- [Configuration](docs/configuration.md): the configuration document, secrets, key rotation and logs.
- IdP setup: [Clerk](docs/idp-clerk.md), [Casdoor](docs/idp-casdoor.md), WeChat mini programs included.
- Deployment: [Cloudflare Workers](docs/deploy-workers.md),
  [Alibaba Cloud Function Compute](docs/deploy-fc.md), [Alibaba Cloud ESA](docs/deploy-esa.md),
  [Node and containers](docs/deploy-node.md).
- [Integrating a product](docs/integrate.md): clients, backends, Go and Python, events and data rules.
- [Changelog](CHANGELOG.md).

## Packages

| Package | For |
|---|---|
| [`@therank/identity-bridge-client`](packages/client/README.md) ([npm](https://www.npmjs.com/package/@therank/identity-bridge-client)) | Browsers, Node.js and WeChat mini programs: token exchange, caching and refresh on demand |
| [`@therank/identity-bridge-server`](packages/server/README.md) ([npm](https://www.npmjs.com/package/@therank/identity-bridge-server)) | Product backends: access token and event verification |

Both share the bridge's release version. Backends in other languages use a JWT library: see
[integrate.md](docs/integrate.md#other-languages).

## Choosing a runtime

One deployment is one issuer, one key set and one configuration. A product can use separate deployments for
Clerk outside mainland China and Casdoor inside it.

| Runtime | Where | Notes |
|---|---|---|
| [Cloudflare Workers](docs/deploy-workers.md) | Outside mainland China | Check the plan's request and CPU limits |
| [Alibaba Cloud ESA](docs/deploy-esa.md) | Mainland China, on an ICP-filed domain | The plan's fetch limit caps webhook fan-out |
| [Alibaba Cloud Function Compute](docs/deploy-fc.md) | Mainland China, on an ICP-filed domain | Runs the Node bundle; account for cold starts and variable size limits |
| [Node](docs/deploy-node.md) | Any host | The Node bundle or the container image, on a host you run |

## Releases

See the [changelog](CHANGELOG.md) for release status. Releases are tagged `vX.Y.Z`; pin a tag for deployment.
The release workflows publish:

- on its [GitHub release](https://github.com/theRank/identity-bridge/releases), `server.mjs`, the single-file
  Node bundle, and `esa.js`, the single-file ESA bundle, each with a `.sha256` file;
- the image `ghcr.io/therank/identity-bridge:X.Y.Z`, for `linux/amd64` and `linux/arm64`; the highest release
  that is not a prerelease also gets `X.Y` and `latest`;
- both npm packages at version `X.Y.Z`.

Workers deployments build from the tag's source.

## Smoke test

`scripts/smoke.ts` checks a running deployment from outside; run it after every deploy. It needs Node 24 or
later, nothing installed, no secret and no IdP token:

```sh
node scripts/smoke.ts https://id.acme.example acme
```

It checks health, public JWKS contents, token exchange error responses and unknown-path handling, and exits
with `1` on any mismatch. It does not exercise a valid IdP token exchange or webhook delivery. Each
`--header 'name: value'` is sent with every request, such as the cookie an
[ESA default domain](docs/deploy-esa.md#default-domain-and-staging) needs; header values are never printed.

## Development

Requires Node 24 or later. The service is TypeScript on Web-standard APIs, with [jose](https://github.com/panva/jose)
as its only runtime dependency. Runtime entries are in `src/runtimes`.

```sh
npm ci
npm test            # Vitest, in the Workers runtime and in plain Node
npm run typecheck   # wrangler types, then tsc over the service, tests, scripts and packages
npm run build       # the Workers bundle (dry run), server.mjs, esa.js and the packages
npm run test:node --workspaces --if-present   # the packages' plain-Node checks, after the build
npm run dev         # a local Worker, reading .dev.vars
```

`node scripts/dev-env.ts` prints throwaway values on `*.example` hosts for local runs; see
[deploy-node.md](docs/deploy-node.md#trying-it-locally).

Build with `npm run build:node` before running the IdP integration checks:

- `node scripts/e2e-casdoor.ts [image]`: token exchange, webhook delivery and user write permissions against a
  throwaway Casdoor container configured as in [the setup guide](docs/idp-casdoor.md). Requires Docker and
  `openssl`; the optional image selects another Casdoor version. CI checks service changes and runs weekly
  against both the pinned version and `latest`.
- `node scripts/e2e-clerk.ts`: token exchange against a dedicated Clerk development instance configured as in
  [the setup guide](docs/idp-clerk.md). Set `CLERK_SECRET_KEY` and either `CLERK_ISSUER` (the Frontend API URL)
  or `CLERK_PUBLISHABLE_KEY`. It creates and deletes test users; webhooks are not covered. CI runs on service
  changes, weekly and manually, but skips fork and Dependabot pull requests. Keep this external-service
  check out of required checks.

## Security

See [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE).
