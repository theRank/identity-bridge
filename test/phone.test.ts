import { describe, expect, it } from 'vitest'
import { CALLING_CODES, internationalNumber } from '../src/phone'

describe('internationalNumber', () => {
    it.each([
        ['13800138000', 'CN', '+8613800138000'],
        ['2087654321', 'US', '+12087654321'],
        ['4165550123', 'CA', '+14165550123'],
        ['7911123456', 'GB', '+447911123456'],
        ['7011234567', 'KZ', '+77011234567'],
        ['61234567', 'HK', '+85261234567'],
    ])('joins %s in %s to %s', (number, region, expected) => {
        expect(internationalNumber(number, region)).toBe(expected)
    })

    // The same digits are two numbers: the region decides
    it('gives a number of two regions the calling code of the one named', () => {
        expect(internationalNumber('2087654321', 'US')).toBe('+12087654321')
        expect(internationalNumber('2087654321', 'CN')).toBe('+862087654321')
    })

    it.each([
        ['an empty number', ''],
        ['a number with its trunk prefix', '013800138000'],
        ['a number already in international form', '+8613800138000'],
        ['a number with a space', '138 0013 8000'],
        ['a number with a hyphen', '138-0013-8000'],
        ['fullwidth digits', '１３８００１３８０００'],
        ['a number followed by a line break', '13800138000\n'],
        ['a number', 13800138000],
        ['null', null],
        ['no number', undefined],
        ['an object', { number: '13800138000' }],
    ])('gives none for %s', (_what, number) => {
        expect(internationalNumber(number, 'CN')).toBeUndefined()
    })

    // Not joined either way: +390212345678 would be right here, and +86013800138000 wrong
    it('gives none for a leading zero even where it belongs to the number', () => {
        expect(internationalNumber('0212345678', 'IT')).toBeUndefined()
        expect(internationalNumber('0123456789', 'CI')).toBeUndefined()
    })

    it.each([
        ['an empty region', ''],
        ['a region in lower case', 'cn'],
        ['an unknown region', 'ZZ'],
        ['the non-geographic region', '001'],
        ['a calling code', '86'],
        ['a region with a space', 'CN '],
        ['a number', 86],
        ['null', null],
        ['no region', undefined],
        ['an array', ['CN']],
    ])('gives none for %s', (_what, region) => {
        expect(internationalNumber('13800138000', region)).toBeUndefined()
    })

    it.each(['__proto__', 'constructor', 'toString', 'valueOf', 'hasOwnProperty'])('gives none for the region %s', (region) => {
        expect(internationalNumber('13800138000', region)).toBeUndefined()
    })
})

describe('CALLING_CODES', () => {
    it('names regions by two capital letters and calling codes by one to three digits', () => {
        for (const [region, code] of CALLING_CODES) {
            expect(region).toMatch(/^[A-Z]{2}$/)
            expect(code).toMatch(/^[1-9]\d{0,2}$/)
        }
    })

    it('holds every region of libphonenumber', () => {
        expect(CALLING_CODES.size).toBe(245)
    })

    it.each([
        ['CN', '86'],
        ['HK', '852'],
        ['MO', '853'],
        ['TW', '886'],
        ['US', '1'],
        ['PR', '1'],
        ['RU', '7'],
        ['IT', '39'],
        ['VA', '39'],
        ['JE', '44'],
        ['XK', '383'],
        ['SG', '65'],
    ])('gives %s the calling code %s', (region, code) => {
        expect(CALLING_CODES.get(region)).toBe(code)
    })
})
