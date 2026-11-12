import type { Deps, LogLine } from '../../src/types'

export const START_MS = 1_760_000_000_000

// Deps with a clock that moves only through `advance`, sequential v4-shaped UUIDs and captured log lines.
// The default fetch rejects, so a test that reaches the network without meaning to fails.
export function fakeDeps(overrides: Partial<Deps> = {}) {
    const logs: LogLine[] = []
    let now = START_MS
    let uuids = 0
    const deps: Deps = {
        fetch: () => Promise.reject(new Error('unexpected fetch')),
        now: () => now,
        randomUUID: () => `00000000-0000-4000-8000-${String(++uuids).padStart(12, '0')}`,
        log: (line) => {
            logs.push(line)
        },
        ...overrides,
    }
    return {
        deps,
        logs,
        advance: (ms: number) => {
            now += ms
        },
    }
}
