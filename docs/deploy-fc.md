# Deploying on Alibaba Cloud Function Compute

The bridge as a Function Compute 3.0 function, running the release's Node bundle as a code package, for
mainland China. It is plain Node 24, the same artifact a deployer can run locally, and it has no limit on
webhook fan-out. [Choosing a runtime](../README.md#choosing-a-runtime) compares the options.

Function Compute's documentation does not describe all of what a deployment meets. What it leaves out is given
here as observed on Function Compute 3.0 in cn-hangzhou in 2026-11; Function Compute's source is not public.

## Pinning a release

The code package is the release's `server.mjs`, zipped alone:

```sh
VERSION=v1.0.0
curl -fsSLO "https://github.com/theRank/identity-bridge/releases/download/$VERSION/server.mjs"
curl -fsSLO "https://github.com/theRank/identity-bridge/releases/download/$VERSION/server.mjs.sha256"
sha256sum -c server.mjs.sha256
zip code.zip server.mjs
```

## Function settings

| Setting | API field | Value |
|---|---|---|
| Runtime | `runtime` | `custom.debian12` |
| Layer | `layers` | Function Compute's official `Nodejs24` layer, by its version ARN, such as `acs:fc:cn-hangzhou:official:layers/Nodejs24/versions/2` |
| Code | `code` | `code.zip` |
| Handler | `handler` | Any non-empty value, such as `index.handler`: the API requires one, and a custom runtime does not use it |
| Startup command | `customRuntimeConfig.command` | `["/opt/nodejs24/bin/node", "server.mjs"]` |
| Listening port | `customRuntimeConfig.port` | `9000` |
| Health check | `customRuntimeConfig.healthCheckConfig` | none |
| Environment variables | `environmentVariables` | `PORT=9000`, `BRIDGE_CONFIG`, `SIGNING_KEYS`, and each `WEBHOOK_SECRET_<SOURCE>` |
| Execution timeout | `timeout` | `60` |
| Instance concurrency | `instanceConcurrency` | more than 1, such as `10` |
| vCPU, memory | `cpu`, `memorySize` | `0.5`, `512` |
| Logging | `logConfig` | a Simple Log Service project and Logstore |

The fields are those of the `CreateFunction` and `UpdateFunction` APIs ([function][fc-function-struct],
[custom runtime][fc-custom-runtime-config]); the console has a setting for each.

Why each one:

- **Runtime and layer.** `custom.debian12` is a custom runtime: Function Compute starts the startup command and
  forwards HTTP requests to the port it listens on ([custom runtime][fc-custom-runtime]). Its official
  `Nodejs24` layer provides Node.js 24, version 24.22.1 in layer version 2, under `/opt/nodejs24/bin`
  ([layers][fc-layers], [layer README][fc-layer-readme]). Function Compute's own newest Node.js runtime is
  `nodejs20` ([runtimes][fc-runtimes]); Node.js 20 reached its end of life on 2026-04-30
  ([Node.js][node-release]), and releases are built and tested on Node.js 24. Pin the layer version and move to a
  newer one deliberately: the layer, not the bridge, decides the Node.js patch release.
  `custom.debian12` is in public preview in some regions only ([custom runtime][fc-custom-runtime]).
- **Port.** Function Compute's default listening port is 9000 ([custom runtime][fc-custom-runtime]), and the
  bridge listens on `PORT`, 8080 by default, so set both. The bridge listens on `0.0.0.0`, as Function Compute
  requires.
- **No health check.** Observed: Function Compute's health check probes port 9000 whatever port the function
  sets. Worse, after an update whose new instances fail it, the old instances keep answering, about half a
  second slower, so a broken configuration passes the smoke test until they are reclaimed. Without the check,
  a new instance whose configuration fails to load answers in [failure mode](api.md#failure-mode) at once, and
  the smoke test catches it. Function Compute documents the check without saying which port it probes
  ([health check][fc-health-check]).
- **Timeout.** The API's default is 3 seconds ([function][fc-function-struct]). A webhook waits up to 5 seconds
  for each product's answer, so 60 seconds leaves room.
- **Concurrency.** An instance serves up to `instanceConcurrency` requests at once
  ([concurrency][fc-concurrency]). The bridge mostly waits on the IdP's keys or on products, so one instance
  handles many requests.
- **Size.** 0.5 vCPU with 512 MB is within Function Compute's allowed ratios
  ([instance types][fc-instance-types]) and enough for the bridge.

## Configuration and secrets

The configuration, the keys and the webhook secrets are environment variables, which Function Compute stores
encrypted at rest ([environment variables][fc-env]).

**Size.** Function Compute documents a limit of 4 KB for all environment variables together
([environment variables][fc-env]). Observed on Function Compute 3.0 in 2026-11, `UpdateFunction` accepted up
to 32 KiB and refused 33 KiB with `Environment variable size is too large (max: 32768, actual: '33792')`.
Keep the minified configuration, the keys and the secrets within the documented 4 KB;
[sizes](configuration.md#sizes) gives typical lengths. A deployment that does not fit needs another runtime:
the bridge reads its configuration only from the environment.

**Who can read them.** `GetFunction` returns the function's environment variables, the keys and secrets
included, to any RAM user allowed the action `fc:GetFunction` on it ([GetFunction][fc-get-function]). Grant
that action only to the people and roles that deploy the bridge.

Changing a variable updates the function, and new instances load it. Then wait for the update, as below, and
run the smoke test.

## HTTP trigger and domain

- Add an HTTP trigger with authentication `anonymous` and the methods `GET`, `POST` and `OPTIONS`
  ([HTTP trigger][fc-http-trigger-config]). The bridge authenticates what needs it, and `OPTIONS` carries the
  CORS preflight, which the bridge answers itself ([HTTP triggers][fc-http-triggers]).
- Bind a custom domain with an ICP filing to the function, with its certificate, and make it the bridge's
  issuer host ([custom domains][fc-custom-domains]). WeChat mini programs call only HTTPS domains with ICP
  filing ([WeChat][wx-network]).
- The trigger's default address, on `fcapp.run`, is for testing only: Function Compute adds
  `Content-Disposition: attachment` to its answers ([HTTP triggers][fc-http-triggers],
  [invoking][fc-http-invoke]).

## Logs

The bridge writes its [log lines](configuration.md#logs) to stdout. Function Compute keeps them only when the
function's logging names a Simple Log Service project and Logstore; with logging off, nothing is kept
([logging][fc-logging]). A function created through the API without `logConfig` has none.

## Cold starts

Observed: an instance idle for 5 to 10 minutes is reclaimed, and the next request waits about 0.7 seconds for a
new one, including Node's start; warm requests take 10 to 20 milliseconds in the region. A client exchanges
about once per `tokenTtlSeconds`, so few requests meet a cold start. To avoid them, keep a minimum of one
instance ([cold starts][fc-cold-start], [minimum instances][fc-min-instances]), which is billed while idle.

## Deploying an update

After `UpdateFunction` or a change of variables, wait until `GetFunction` reports `state` `Active` and
`lastUpdateStatus` `Successful` ([function][fc-function-struct], [states][fc-states]), then run the smoke test:

```sh
node scripts/smoke.ts https://id.cn.acme.example acme
```

Observed: a code package function serves the new code at once. [What the smoke test checks](../README.md#smoke-test).

## Key rotation

Follow [rotating the signing key](configuration.md#rotating-the-signing-key): update `SIGNING_KEYS`, wait for
the update, run the smoke test, and later update it again without the retired key. During a rotation
`SIGNING_KEYS` holds two keys; check that everything still fits within the documented 4 KB.

## Container images

A custom container image is the fallback only, when the code package cannot be used. Observed: cold starts take
2 to 3 seconds instead of 0.7. The image must be in Alibaba Cloud Container Registry, in the function's account
and region; its Personal Edition has no service level agreement, so use the Enterprise Edition for production
([container functions][fc-container]). Mirror the [GHCR image](deploy-node.md#artifacts) there.

[fc-function-struct]: https://www.alibabacloud.com/help/en/functioncompute/api-fc-2023-03-30-struct-function
[fc-custom-runtime-config]: https://www.alibabacloud.com/help/en/functioncompute/api-fc-2023-03-30-struct-customruntimeconfig
[fc-custom-runtime]: https://www.alibabacloud.com/help/en/functioncompute/principles-1
[fc-layers]: https://www.alibabacloud.com/help/en/functioncompute/configure-common-layers-for-a-function-1
[fc-layer-readme]: https://github.com/awesome-fc/awesome-layers/blob/453f049114adb7abb332e15dca3a17e9e8facdfe/docs/Nodejs24/README.md
[fc-runtimes]: https://www.alibabacloud.com/help/en/functioncompute/runtime-intro
[node-release]: https://github.com/nodejs/Release#end-of-life-releases
[fc-health-check]: https://www.alibabacloud.com/help/en/functioncompute/configure-a-custom-health-check-policy-for-instances-1
[fc-concurrency]: https://www.alibabacloud.com/help/en/functioncompute/configure-the-concurrency-of-a-single-instance
[fc-instance-types]: https://www.alibabacloud.com/help/en/functioncompute/instance-types-and-specifications
[fc-env]: https://www.alibabacloud.com/help/en/functioncompute/environment-variables
[fc-get-function]: https://www.alibabacloud.com/help/en/functioncompute/api-fc-2023-03-30-getfunction
[fc-http-trigger-config]: https://www.alibabacloud.com/help/en/functioncompute/api-fc-2023-03-30-struct-httptriggerconfig
[fc-http-triggers]: https://www.alibabacloud.com/help/en/functioncompute/http-triggers-overview
[fc-http-invoke]: https://www.alibabacloud.com/help/en/functioncompute/http-trigger-invoking-function
[fc-custom-domains]: https://www.alibabacloud.com/help/en/functioncompute/configure-custom-domain-names
[fc-logging]: https://www.alibabacloud.com/help/en/functioncompute/configure-the-logging-feature
[fc-cold-start]: https://www.alibabacloud.com/help/en/functioncompute/best-practice-for-reducing-cold-start-latencies
[fc-min-instances]: https://www.alibabacloud.com/help/en/functioncompute/configure-launch-snapshot-and-auto-scaling-rules
[fc-states]: https://www.alibabacloud.com/help/en/functioncompute/states-of-custom-container-functions
[fc-container]: https://www.alibabacloud.com/help/en/functioncompute/create-a-custom-container-function-in-a-container-runtime
[wx-network]: https://developers.weixin.qq.com/miniprogram/dev/framework/ability/network.html
