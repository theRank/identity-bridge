import { cloudflareTest } from '@cloudflare/vitest-plugin'
import { defineConfig } from 'vitest/config'

export default defineConfig({
    plugins: [
        cloudflareTest({
            wrangler: { configPath: './wrangler.jsonc' },
            miniflare: {
                bindings: {},
            },
        }),
    ],
    test: {
        // Plain-Node checks of the built packages live in packages/*/test-node/, outside this pool
        include: ['test/**/*.test.ts', 'packages/*/test/**/*.test.ts'],
    },
})
