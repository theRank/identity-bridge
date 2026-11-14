import { cloudflareTest } from '@cloudflare/vitest-plugin'
import { configDefaults, defineConfig } from 'vitest/config'
import { clerkConfigJson } from './test/helpers/config'
import { bridgeSigningKeys } from './test/helpers/keys'
import { CLERK_SECRET } from './test/helpers/webhooks'

// Two projects, so one run covers both runtimes: the core and the Workers entry in the Workers runtime, and the
// Node entry in plain Node, where it is reached through real HTTP
export default defineConfig({
    test: {
        projects: [
            {
                plugins: [
                    cloudflareTest(async () => ({
                        wrangler: { configPath: './wrangler.jsonc' },
                        miniflare: {
                            // For the Workers entry's tests: a test configuration, its webhook source's secret and a
                            // signing key generated per run, so no key is ever committed
                            bindings: {
                                BRIDGE_CONFIG: clerkConfigJson,
                                SIGNING_KEYS: (await bridgeSigningKeys()).json,
                                WEBHOOK_SECRET_CLERK_ACME: CLERK_SECRET,
                            },
                        },
                    })),
                ],
                test: {
                    name: 'workers',
                    // Plain-Node checks of the built packages live in packages/*/test-node/, outside this pool
                    include: ['test/**/*.test.ts', 'packages/*/test/**/*.test.ts'],
                    exclude: [...configDefaults.exclude, 'test/node/**'],
                },
            },
            {
                test: {
                    name: 'node',
                    environment: 'node',
                    include: ['test/node/**/*.test.ts'],
                },
            },
        ],
    },
})
