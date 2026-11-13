import { afterEach, describe, expect, it, vi } from 'vitest'
import { cryptoSelfTest } from '../src/selftest'

// The result is memoized per module instance, so each failure case loads a fresh one
async function freshSelfTest(): Promise<() => Promise<boolean>> {
    vi.resetModules()
    return (await import('../src/selftest')).cryptoSelfTest
}

function algorithmName(algorithm: string | { name: string }): string {
    return typeof algorithm === 'string' ? algorithm : algorithm.name
}

const subtle = crypto.subtle
const original = {
    digest: subtle.digest.bind(subtle),
    sign: subtle.sign.bind(subtle),
    verify: subtle.verify.bind(subtle),
    generateKey: subtle.generateKey.bind(subtle),
}

afterEach(() => {
    vi.restoreAllMocks()
})

describe('cryptoSelfTest', () => {
    it('passes in the Workers runtime', async () => {
        expect(await cryptoSelfTest()).toBe(true)
    })

    it('returns the same promise on every call', () => {
        const first = cryptoSelfTest()
        expect(cryptoSelfTest()).toBe(first)
        expect(cryptoSelfTest()).toBe(first)
    })

    it('runs its checks once per isolate', async () => {
        const generateKey = vi.spyOn(subtle, 'generateKey')
        const selfTest = await freshSelfTest()
        expect(await Promise.all([selfTest(), selfTest(), selfTest()])).toEqual([true, true, true])
        expect(await selfTest()).toBe(true)
        expect(generateKey).toHaveBeenCalledTimes(1)
    })

    it('fails when SHA-1 gives a wrong digest', async () => {
        vi.spyOn(subtle, 'digest').mockImplementation(async (algorithm, data) =>
            algorithmName(algorithm) === 'SHA-1' ? new ArrayBuffer(20) : original.digest(algorithm, data),
        )
        expect(await (await freshSelfTest())()).toBe(false)
    })

    it('fails when HMAC-SHA256 gives a wrong answer', async () => {
        vi.spyOn(subtle, 'sign').mockImplementation(async (algorithm, key, data) =>
            algorithmName(algorithm) === 'HMAC' ? new ArrayBuffer(32) : original.sign(algorithm, key, data),
        )
        expect(await (await freshSelfTest())()).toBe(false)
    })

    it.each(['ECDSA', 'RSASSA-PKCS1-v1_5'])('fails when %s verification accepts any signature', async (name) => {
        vi.spyOn(subtle, 'verify').mockImplementation(async (algorithm, key, signature, data) =>
            algorithmName(algorithm) === name ? true : original.verify(algorithm, key, signature, data),
        )
        expect(await (await freshSelfTest())()).toBe(false)
    })

    it.each(['ECDSA', 'RSASSA-PKCS1-v1_5'])('fails when %s verification rejects every signature', async (name) => {
        vi.spyOn(subtle, 'verify').mockImplementation(async (algorithm, key, signature, data) =>
            algorithmName(algorithm) === name ? false : original.verify(algorithm, key, signature, data),
        )
        expect(await (await freshSelfTest())()).toBe(false)
    })

    const unsupported = () => {
        throw new Error('unsupported')
    }

    it.each([
        ['generateKey', () => vi.spyOn(subtle, 'generateKey').mockRejectedValue(new Error('unsupported'))],
        ['digest', () => vi.spyOn(subtle, 'digest').mockRejectedValue(new Error('unsupported'))],
        ['importKey', () => vi.spyOn(subtle, 'importKey').mockRejectedValue(new Error('unsupported'))],
        ['sign', () => vi.spyOn(subtle, 'sign').mockImplementation(unsupported)],
    ])('resolves false rather than rejecting when %s throws', async (_, fault) => {
        fault()
        await expect((await freshSelfTest())()).resolves.toBe(false)
    })
})
