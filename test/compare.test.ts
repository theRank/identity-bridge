import { describe, expect, it } from 'vitest'
import { constantTimeEqual } from '../src/crypto/compare'

const bytes = (text: string) => new TextEncoder().encode(text)

describe('constantTimeEqual', () => {
    it('is true for equal bytes', () => {
        expect(constantTimeEqual(bytes('v1,c2lnbmF0dXJl'), bytes('v1,c2lnbmF0dXJl'))).toBe(true)
    })

    it('is true for two empty arrays', () => {
        expect(constantTimeEqual(new Uint8Array(), new Uint8Array())).toBe(true)
    })

    it('compares bytes, not the arrays holding them', () => {
        const a = bytes('secret')
        expect(constantTimeEqual(a, Uint8Array.from(a))).toBe(true)
    })

    it.each([
        ['the first byte', 'xecret', 'secret'],
        ['the last byte', 'secreT', 'secret'],
        ['a missing last byte', 'secre', 'secret'],
        ['an extra last byte', 'secrets', 'secret'],
        ['an empty input', '', 'secret'],
        ['the case of every byte', 'SECRET', 'secret'],
    ])('is false when they differ in %s', (_, a, b) => {
        expect(constantTimeEqual(bytes(a), bytes(b))).toBe(false)
        expect(constantTimeEqual(bytes(b), bytes(a))).toBe(false)
    })

    it('tells apart bytes whose XOR with another pair would cancel out', () => {
        expect(constantTimeEqual(Uint8Array.of(1, 2), Uint8Array.of(2, 1))).toBe(false)
        expect(constantTimeEqual(Uint8Array.of(0xff, 0x00), Uint8Array.of(0x00, 0xff))).toBe(false)
    })
})
