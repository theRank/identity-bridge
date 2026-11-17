# Deploying on Cloudflare Workers

The bridge as a Cloudflare Worker, for deployments outside mainland China. Cloudflare's global network has no
data centers in mainland China; its China Network, which does, needs an Enterprise plan and an ICP filing for
each domain ([Cloudflare][cf-china], [China Network][cf-china-network]). For mainland China, see
[Choosing a runtime](../README.md#choosing-a-runtime).

## Pinning a release

A Workers deployment builds from the source of a release tag:

```sh
git clone --depth 1 --branch v1.0.0 https://github.com/theRank/identity-bridge.git
cd identity-bridge
npm ci
```

The repository's `wrangler.jsonc` names the entry, `src/runtimes/workers.ts`, and the compatibility date, turns
[Workers Logs](#logs) on, and holds nothing deployment-specific: no routes, and `workers_dev` and preview URLs
off ([configuration][cf-wrangler-config]). Every `wrangler deploy` and `wrangler secret`
command below passes the Worker's name with `--name`.

## Configuration and secrets

`BRIDGE_CONFIG` is a variable; `SIGNING_KEYS` and the webhook secrets are secrets.

```sh
npx wrangler deploy --name identity-bridge-acme --var "BRIDGE_CONFIG:$(cat bridge-config.json)"
npx wrangler secret put SIGNING_KEYS --name identity-bridge-acme < signing-keys.json
npx wrangler secret put WEBHOOK_SECRET_CLERK_ACME --name identity-bridge-acme < webhook-secret-clerk-acme
```

- `--var` takes `key:value` pairs and passes the value to the Worker as a string
  ([`wrangler deploy`][cf-wrangler-deploy]). wrangler splits a pair at its first colon
  ([source][wrangler-var-source]), so the JSON passes as it is.
- A deploy replaces variables set elsewhere, such as in the dashboard, unless `--keep-vars` is given, and never
  deletes secrets ([`wrangler deploy`][cf-wrangler-deploy]). Pass `BRIDGE_CONFIG` on every deploy.
- Each `wrangler secret put` creates a new version of the Worker and deploys it at once
  ([`wrangler secret`][cf-wrangler-secret]). It reads the value from standard input when that is not a
  terminal, and drops trailing whitespace ([source][wrangler-secret-source]), so a file's final newline does no
  harm.
- Until the secrets are in, the first deploy answers in [failure mode](api.md#failure-mode): `/healthz` is
  `503`, and a `runtime_load_failed` line names the missing secret. `wrangler deploy --secrets-file` uploads
  secrets with the code instead ([secrets][cf-secrets]).

Instead of `--var`, `BRIDGE_CONFIG` can live in a wrangler configuration of your own, under `vars`, as a
string or as a JSON object ([environment variables][cf-vars]); the Worker accepts both. Keep that file with
your deployment, with `main` pointing at `src/runtimes/workers.ts` of the checkout, and pass it with
`--config`.

## Domain

Attach the issuer's host name to the Worker as a Custom Domain, in the dashboard or through `routes` with
`custom_domain` in a wrangler configuration of your own ([custom domains][cf-custom-domains]). The issuer's host
is where the SDKs reach the bridge ([issuer](api.md#issuer)).

## Limits and abuse

- On the Workers Free plan an account gets 100,000 requests a day and a request 10 milliseconds of CPU time
  ([limits][cf-limits]). An exchange verifies the IdP's signature and signs a token; measure its CPU time, and
  move to the Paid plan if it comes close to the limit.
- `/token` is public. Limit request rates on the zone with a rate limiting rule ([rate limiting][cf-rate-limit]).

## Logs

The Worker writes each [log line](configuration.md#logs) with `console.log`. Workers Logs keeps them only when
the Worker's observability setting is on ([Workers Logs][cf-logs]), and a Worker that wrangler deploys without
the setting has it off. The repository's `wrangler.jsonc` therefore turns it on, without invocation logs: those
are Cloudflare's own record of each request, which the bridge's [promise about its logs](configuration.md#logs)
does not cover. A wrangler configuration of your own needs the same lines:

```jsonc
"observability": { "enabled": true, "logs": { "invocation_logs": false } }
```

On the Free plan Workers Logs keeps 200,000 log events a day for three days ([Workers Logs][cf-logs]). Follow
the lines live with `npx wrangler tail identity-bridge-acme` ([`wrangler tail`][cf-tail]).

## Smoke test

After every deploy:

```sh
node scripts/smoke.ts https://id.acme.example acme
```

[What it checks](../README.md#smoke-test).

## Key rotation

Follow [rotating the signing key](configuration.md#rotating-the-signing-key): put the new `SIGNING_KEYS` with
`wrangler secret put`, run the smoke test, and later put it again without the retired key. Every isolate loads
the new secret, since a new version starts new isolates.

## Upgrading

Check out the new tag in the shallow clone, reinstall, and deploy with the same `--name` and `--var`:

```sh
git fetch --depth 1 origin tag v1.1.0
git checkout v1.1.0
npm ci
```

Or clone the new tag afresh, as above.

## Trying it locally

`wrangler dev` reads `.dev.vars`, which `scripts/dev-env.ts` can write with throwaway values on `*.example`
hosts:

```sh
node scripts/dev-env.ts > .dev.vars
npm run dev
node scripts/smoke.ts http://localhost:8787 acme
```

`.dev.vars` is ignored by git.

[cf-china]: https://developers.cloudflare.com/support/troubleshooting/general-troubleshooting/geographic-traffic-routing/#why-are-visitors-in-mainland-china-served-from-data-centers-outside-china
[cf-china-network]: https://developers.cloudflare.com/china-network/#availability
[cf-wrangler-config]: https://developers.cloudflare.com/workers/wrangler/configuration/#inheritable-keys
[cf-wrangler-deploy]: https://developers.cloudflare.com/workers/wrangler/commands/workers/#deploy
[cf-wrangler-secret]: https://developers.cloudflare.com/workers/wrangler/commands/workers/#secret-put
[cf-secrets]: https://developers.cloudflare.com/workers/configuration/secrets/#upload-secrets-alongside-code
[cf-vars]: https://developers.cloudflare.com/workers/configuration/environment-variables/#add-environment-variables-via-wrangler
[cf-custom-domains]: https://developers.cloudflare.com/workers/configuration/routing/custom-domains/
[cf-limits]: https://developers.cloudflare.com/workers/platform/limits/#account-plan-limits
[cf-rate-limit]: https://developers.cloudflare.com/waf/rate-limiting-rules/
[cf-logs]: https://developers.cloudflare.com/workers/observability/logs/workers-logs/
[cf-tail]: https://developers.cloudflare.com/workers/wrangler/commands/workers/#tail
[wrangler-var-source]: https://github.com/cloudflare/workers-sdk/blob/cc238b23844081895df4145172512bb34e9be87a/packages/wrangler/src/utils/collectKeyValues.ts#L18-L39
[wrangler-secret-source]: https://github.com/cloudflare/workers-sdk/blob/cc238b23844081895df4145172512bb34e9be87a/packages/wrangler/src/secret/index.ts#L174-L179
