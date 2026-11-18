# Deploying on Alibaba Cloud ESA

Run the bridge as an ESA Functions and Pages routine. The [fetch limit](#fetch-limit-and-fan-out) caps webhook
fan-out; [Choosing a runtime](../README.md#choosing-a-runtime) compares alternatives. Observations below are
from the free plan in 2026-11.

## Activating

Activate Functions and Pages with a plan ([billing][esa-billing]); observed, until then creating a routine fails
with `ServiceNotOpen`. The free plan includes 100 Credits a month, and when a free plan's Credits run out the
service stops, rather than billing more ([billing][esa-billing]). The plan also sets the limits below.

## Deploying

A deployment uses the release's `esa.js`, a single file with jose built in, and the repository's
`scripts/deploy-esa.ts`, from a checkout of the same tag:

```sh
git clone --depth 1 --branch v1.0.0 https://github.com/theRank/identity-bridge.git
cd identity-bridge
curl -fsSLO https://github.com/theRank/identity-bridge/releases/download/v1.0.0/esa.js
curl -fsSLO https://github.com/theRank/identity-bridge/releases/download/v1.0.0/esa.js.sha256
sha256sum -c esa.js.sha256

export ALIBABA_CLOUD_ACCESS_KEY_ID=<access key id>
read -rs ALIBABA_CLOUD_ACCESS_KEY_SECRET && export ALIBABA_CLOUD_ACCESS_KEY_SECRET
node scripts/deploy-esa.ts --name identity-bridge-acme --bundle esa.js --vars bridge.env
```

The script needs Node 24 or later and nothing installed. `read -rs`, in bash or zsh, takes the AccessKey secret
without showing it or keeping it in the shell's history; in a pipeline, take it from the CI system's secret store
or a credentials file instead. Never type the secret into a command line.

| Option | Meaning |
|---|---|
| `--name <routine>` | The routine: lowercase letters, digits and `-`, starting with a letter, at least 2 characters |
| `--bundle <file>` | The `esa.js` to deploy |
| `--vars <file>` | The [variables file](#variables) |
| `--env staging\|production` | The environment, `production` by default |
| `--endpoint <host>` | The ESA OpenAPI endpoint, `esa.cn-hangzhou.aliyuncs.com` by default |
| `--print-access-token` | Also print the access token of the [default domain](#default-domain-and-staging), a credential: see there |

In order, it:

1. creates the routine unless it exists;
2. sets the file's variables in the environment, `BRIDGE_CONFIG` as plain text and the others as secrets, and
   warns about bridge variables the environment holds that the file lacks, deleting none;
3. creates a code version bound to the environment, uploads the bundle into it, and waits until it is
   available;
4. deploys that version to all of the environment's requests;
5. prints the routine's default domain, and for staging the addresses that serve staging.

```text
routine identity-bridge-acme: exists
production variables set: BRIDGE_CONFIG (plain_text), SIGNING_KEYS (secret_text), WEBHOOK_SECRET_CASDOOR_ACME (secret_text)
code version 1794600000000000000: uploaded
code version 1794600000000000000: available
production: code version 1794600000000000000 deployed to 100 percent of requests
default domain: https://identity-bridge-acme-<account id>.debug.er.aliyun-esa.net
```

It exits with `0` once deployed, `1` when a step fails, and `2` for a usage error. It never prints a variable's
value or the AccessKey: an error gives the API's code and message, and for the call that carries the values only
its code.

### The AccessKey

The script calls the ESA OpenAPI, version 2024-09-10, with the AccessKey of a RAM user. Give that user a policy of
its own that allows only the actions the script calls: `esa:GetRoutine`, `esa:CreateRoutine`,
`esa:SetRoutineEnvironmentVariables`, `esa:ListRoutineEnvironmentVariables`,
`esa:CreateRoutineWithAssetsCodeVersion`, `esa:GetRoutineCodeVersionInfo`, `esa:CreateRoutineCodeDeployment`,
`esa:GetRoutineStagingEnvIp` and, for `--print-access-token`, `esa:GetRoutineAccessToken`. The system policy
`AliyunESAFullAccess` ([policies][esa-ram-policies]) also covers them, but grants every other ESA action too
(`esa:*`, [`AliyunESAFullAccess`][esa-full-access]). Some of these actions have no page in ESA's API reference
([API overview][esa-api-overview]); ESA's SDK has them ([SDK][esa-sdk]).

### Why not ESA's CLI

ESA's own CLI is not used, for two observed reasons:

- It refuses a variable value over 200 characters ([source][esa-cli-limit]), which the configuration and a
  rotation's `SIGNING_KEYS` exceed. ESA itself accepts them: the check runs only in the CLI.
- A code version reaches the environment's variables only when it is created bound to that environment,
  through `CreateRoutineWithAssetsCodeVersion` with `DeployEnv`. A version created another way, such as through
  `CommitRoutineStagingCode`, runs without the variables and says nothing; the bridge would then answer in
  failure mode. ESA's documentation says only that variables take effect once a new version is generated and
  released ([variables][esa-variables]).

## Variables

The variables file holds one `NAME=value` per line, as `node scripts/dev-env.ts` prints them:

```text
BRIDGE_CONFIG={"issuer":"https://id.cn.acme.example",...}
SIGNING_KEYS={"active":{"kty":"EC","crv":"P-256","x":"...","y":"...","d":"..."}}
WEBHOOK_SECRET_CASDOOR_ACME=...
```

- Only `BRIDGE_CONFIG`, `SIGNING_KEYS` and `WEBHOOK_SECRET_*` names are accepted, each once and not empty.
- The value is everything after the first `=`, quotes included. Blank lines and lines starting with `#` are
  skipped.
- An error names the line by its number, never by its text, which may be a stray secret.
- Keep the file out of version control. Write it under `umask 077`, so only you can read it, and delete it
  once deployed.

ESA stores secret variables encrypted and passes all variables to the routine ([variables][esa-variables]).

**Capacity.** The free plan allows 16 KiB of function variables, and the Advanced plan 64 KiB
([billing][esa-billing]). Observed: the free plan's limit is 16 KiB (16,384 characters of names and
values) in total, with no limit per value. Over it, the script reports ESA's error `400019`.
[Sizes](configuration.md#sizes) covers what to count.

## Fetch limit and fan-out

ESA limits the `fetch` calls of one request: 10 on the free plan and 100 on Advanced, according to its billing
page ([billing][esa-billing]); its overview says 4 ([overview][esa-overview]). Observed: the free plan allows 10,
and the eleventh throws.

Each webhook delivery to a product is one `fetch`. A webhook source therefore relays to at most 10 products on
the free plan, or 100 on Advanced. Observed: a source with 11 products failed its eleventh delivery on every
retry. The bridge cannot know the plan, so it does not check this; keep each source's `products` within the
limit. A token exchange makes at most one `fetch`, for the IdP's keys.

## Default domain and staging

- **Default domain.** A routine's default domain, `<routine>-<account id>.debug.er.aliyun-esa.net`, is for
  testing only, and since 2026-04 asks for a token ([notice][esa-test-domain]). Observed: it answers `401`
  without the token, sent as the cookie `esa_er_token`, and the token lasts 60 minutes. `--print-access-token`
  prints it, with the smoke test command.

  The token is a credential: for 60 minutes it opens the default domain, which serves production, to whoever
  holds it. Keep it out of CI logs and shell history: write the script's output to a file only you can read,
  and pass the token to the smoke test from a file.

  ```sh
  umask 077
  node scripts/deploy-esa.ts --name identity-bridge-acme --bundle esa.js --vars bridge.env --print-access-token > deploy.out
  sed -n 's/^access token: //p' deploy.out > esa-token
  node scripts/smoke.ts https://identity-bridge-acme-<account id>.debug.er.aliyun-esa.net acme --header "cookie: esa_er_token=$(cat esa-token)"
  rm deploy.out esa-token
  ```

  The smoke test never prints header values.

- **Staging.** Observed: the default domain serves production. Staging answers only on ESA's staging addresses
  ([overview][esa-overview]), which the script prints for `--env staging`. Reach them with `curl --resolve`, or
  with a hosts-file line for the smoke test. An environment with no deployment answers ESA's own HTML page with
  status 582, "Version retrieval failed".

## Production domain

Production serves an ICP-filed domain added to ESA as a site, bound to the routine through a custom domain or a
route ([triggers][esa-triggers], [ICP filing][esa-icp]). Then run the smoke test against that domain, without
the cookie:

```sh
node scripts/smoke.ts https://id.cn.acme.example acme
```

Not yet verified with this release: the binding to a site, the smoke test through it, and where ESA shows a
routine's log lines. [What the smoke test checks](../README.md#smoke-test).

## Other limits

- **CPU.** 100 milliseconds per request ([billing][esa-billing]). Observed from Hangzhou: warm requests take 8 to
  12 milliseconds, no request came near the limit, and no cold start showed after a deployment.
- **Code size.** 4 MB ([overview][esa-overview]); the build fails when `esa.js` exceeds it.
- **Web APIs.** ESA's list of runtime APIs ([runtime APIs][esa-runtime-api]) leaves out `AbortController` and
  `AbortSignal.timeout`, which the bridge uses. Observed: both work, and `AbortSignal.timeout` rejects with an
  error named `Error` rather than `TimeoutError`. JWKS fetches and webhook deliveries have independent
  5-second timers, so their deadlines do not depend on the runtime's abort error name or signal handling.
  `URL.parse` is missing, and the bridge does not use it.
- **`Vary`.** Observed: ESA adds `Accept-Encoding` to the bridge's `Vary: Origin`, which does no harm.

## Key rotation

Follow [key rotation](configuration.md#rotating-the-signing-key), updating `SIGNING_KEYS` in the variables
file and rerunning the deploy script at each step. The script binds each new code version to those variables.

## Upgrading

Check out the new tag in the shallow clone, download that release's `esa.js`, and run the script with the same
options:

```sh
git fetch --depth 1 origin tag v1.1.0
git checkout v1.1.0
curl -fsSLO https://github.com/theRank/identity-bridge/releases/download/v1.1.0/esa.js
curl -fsSLO https://github.com/theRank/identity-bridge/releases/download/v1.1.0/esa.js.sha256
sha256sum -c esa.js.sha256
```

Or clone the new tag afresh, as above.

[esa-billing]: https://help.aliyun.com/en/edge-security-acceleration/esa/user-guide/functions-and-pages-billing
[esa-overview]: https://www.alibabacloud.com/help/en/edge-security-acceleration/esa/user-guide/what-is-functions-and-pages/
[esa-variables]: https://www.alibabacloud.com/help/en/edge-security-acceleration/esa/user-guide/function-variable
[esa-ram-policies]: https://www.alibabacloud.com/help/en/edge-security-acceleration/esa/security-and-compliance/edge-security-acceleration-system-permission-policy-reference
[esa-full-access]: https://www.alibabacloud.com/help/en/ram/developer-reference/aliyunesafullaccess
[esa-api-overview]: https://www.alibabacloud.com/help/en/edge-security-acceleration/esa/api-esa-2024-09-10-overview
[esa-sdk]: https://unpkg.com/@alicloud/esa20240910@3.16.1/dist/client.d.ts
[esa-cli-limit]: https://github.com/aliyun/alibabacloud-esa-cli/blob/a65770fef847f09f54847da3f3b4ee9e58bea060/src/commands/env/utils.ts#L104-L106
[esa-test-domain]: https://www.alibabacloud.com/en/notice/product_changechange_announcement_for_esa_functions_and_pages_6cf
[esa-triggers]: https://www.alibabacloud.com/help/en/edge-security-acceleration/esa/user-guide/trigger
[esa-icp]: https://www.alibabacloud.com/help/en/edge-security-acceleration/esa/getting-started/add-your-website-to-esa
[esa-runtime-api]: https://www.alibabacloud.com/help/en/edge-security-acceleration/esa/user-guide/runtimeapi-manual
