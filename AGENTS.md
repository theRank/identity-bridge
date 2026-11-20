# identity-bridge

Guidance for coding agents. `README.md` describes the project and `docs/` holds its documentation.

## Tech Stack

TypeScript (strict `tsc`, no linter) on Web-standard APIs, Node >= 24, npm workspaces. `jose` is the only runtime
dependency. Vitest with the Cloudflare plugin; wrangler and esbuild for bundles.

| Path | Purpose |
|---|---|
| `src/` | The service: router, config, keys, ids, tokens, `idp/`, `routes/`, `webhooks/` |
| `src/runtimes/` | Entries for Workers, Node and ESA |
| `packages/client`, `packages/server` | npm SDKs, versioned with the service |
| `scripts/` | Builds, ESA deploy, smoke test, IdP e2e checks |
| `test/`, `test/node/` | Vitest: Workers-runtime project, plain-Node project |
| `docs/` | Documentation |

## Commands

```sh
npm ci
npm run typecheck
npm test
npm run build
npm run test:node --workspaces --if-present   # after the build
node scripts/e2e-casdoor.ts   # after build:node; Docker, openssl
node scripts/e2e-clerk.ts     # after build:node; CLERK_* variables
```

CI (`.github/workflows/test.yml`) runs typecheck, test, build and the packages' Node checks, in that order.

## Git Rules

- Branch naming: `<type>/<short-name>`, such as `feat/casdoor-event-id`
- Commit format: `type(scope): message`; scopes so far: config, crypto, idp, token, webhooks, runtime, sdk,
  casdoor, clerk, repo, deps
- PRs are squash-merged; the PR title becomes the commit on `main`
- Releases are tags `vX.Y.Z`, which trigger `release.yml` and `publish.yml`

## Change Rules

- A wire contract change updates the service, both SDKs, `docs/api.md` and `CHANGELOG.md` together. A breaking
  one is marked `!` and is a new major version of all three
- A behavior change gets a line in the unreleased section of `CHANGELOG.md`
