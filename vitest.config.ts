import { cloudflareTest } from '@cloudflare/vitest-plugin'
import { configDefaults, defineConfig } from 'vitest/config'
import { clerkConfigJson } from './test/helpers/config'
import { bridgeSigningKeys } from './test/helpers/keys'
import { CLERK_SECRET } from './test/helpers/webhooks'

// Two projects, so one run covers both the Workers runtime and plain Node
export default defineConfig({
    test: {
        projects: [
            {
                plugins: [
                    cloudflareTest(async () => ({
                        wrangler: { configPath: './wrangler.jsonc' },
                        miniflare: {
                            // For the Workers and ESA entries' tests, with a signing key generated per run so none
                            // is committed
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
