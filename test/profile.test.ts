import { describe, expect, it } from 'vitest'
import { cleanProfile } from '../src/profile'
import type { RawProfile } from '../src/types'

const FULL: RawProfile = {
    email: 'ada@acme.example',
    emailVerified: true,
    phone: '+14155550123',
    phoneVerified: true,
    name: 'Ada Lovelace',
    picture: 'https://img.acme.example/ada.png',
}

// The same number in another script's digits; zero is the code point of that script's 0
function otherDigits(phone: string, zero: number): string {
    return phone.replace(/[0-9]/g, (digit) => String.fromCharCode(zero + Number(digit)))
}

// Resolving the flags is the caller's job; a value that slips through unresolved must not count as verified
const TRUTHY_FLAGS: unknown[] = ['true', 'false', 1, 'yes', {}, [], new Boolean(true)]

const NOT_STRINGS: unknown[] =[null, 42, 0, true, false, {}, [], ['ada@acme.example'], new String('ada@acme.example'), Symbol('x'), 10n]

describe('cleanProfile', () => {
    it('keeps a verified email, a verified E.164 phone, a name and an https picture', () => {
        expect(cleanProfile(FULL)).toEqual({
            email: 'ada@acme.example',
            phoneNumber: '+14155550123',
            name: 'Ada Lovelace',
            picture: 'https://img.acme.example/ada.png',
        })
    })

    it('gives an empty profile when nothing is known', () => {
        const profile = cleanProfile({ emailVerified: false, phoneVerified: false })
        expect(profile).toEqual({})
        expect(Object.keys(profile)).toEqual([])
    })

    it('leaves out members it drops rather than setting them to undefined', () => {
        const profile = cleanProfile({ ...FULL, emailVerified: false, phone: 7, name: '  ', picture: 'http://img.acme.example/ada.png' })
        expect(Object.keys(profile)).toEqual([])
    })

    it.each(NOT_STRINGS)('drops the non-string value %s from every member', (value) => {
        expect(cleanProfile({ email: value, emailVerified: true, phone: value, phoneVerified: true, name: value, picture: value })).toEqual({})
    })

    it('does not change its input', () => {
        const raw = { ...FULL, name: '  Ada  ' }
        cleanProfile(raw)
        expect(raw).toEqual({ ...FULL, name: '  Ada  ' })
    })

    describe('email', () => {
        it('drops an unverified email', () => {
            expect(cleanProfile({ ...FULL, emailVerified: false })).not.toHaveProperty('email')
        })

        it.each(TRUTHY_FLAGS)('drops an email whose verified flag is %j rather than true', (flag) => {
            expect(cleanProfile({ ...FULL, emailVerified: flag as boolean })).not.toHaveProperty('email')
        })

        it.each(['', 'ada', 'ada.acme.example'])('drops %j, which has no @', (email) => {
            expect(cleanProfile({ ...FULL, email })).not.toHaveProperty('email')
        })

        it('keeps a verified email as given', () => {
            expect(cleanProfile({ ...FULL, email: 'Ada+Bridge@ACME.example' }).email).toBe('Ada+Bridge@ACME.example')
            expect(cleanProfile({ ...FULL, email: '@' }).email).toBe('@')
        })
    })

    describe('phone', () => {
        it('drops an unverified phone', () => {
            expect(cleanProfile({ ...FULL, phoneVerified: false })).not.toHaveProperty('phoneNumber')
        })

        it.each(TRUTHY_FLAGS)('drops a phone whose verified flag is %j rather than true', (flag) => {
            expect(cleanProfile({ ...FULL, phoneVerified: flag as boolean })).not.toHaveProperty('phoneNumber')
        })

        it.each(['+1234567', '+123456789012345', '+8613800138000', '+442071838750'])('keeps %s', (phone) => {
            expect(cleanProfile({ ...FULL, phone }).phoneNumber).toBe(phone)
        })

        it.each([
            '',
            '+',
            '+123456',
            '+1234567890123456',
            '+0123456789',
            '14155550123',
            '+1 415 555 0123',
            '+1-415-555-0123',
            '(415) 555-0123',
            '+14155550123\n',
            ' +14155550123',
            otherDigits('+14155550123', 0xff10),
            otherDigits('+12345678', 0x0660),
        ])('drops %j, which is not E.164', (phone) => {
            expect(cleanProfile({ ...FULL, phone })).not.toHaveProperty('phoneNumber')
        })
    })

    describe('name', () => {
        it('trims the name', () => {
            expect(cleanProfile({ ...FULL, name: '  Ada Lovelace \n' }).name).toBe('Ada Lovelace')
            expect(cleanProfile({ ...FULL, name: '\u3000王小明\u3000' }).name).toBe('王小明')
        })

        it.each(['', ' ', '\t\n', '\u3000'])('drops %j, which is empty once trimmed', (name) => {
            expect(cleanProfile({ ...FULL, name })).not.toHaveProperty('name')
        })

        it('keeps a name without any verified flag', () => {
            expect(cleanProfile({ name: 'Ada', emailVerified: false, phoneVerified: false })).toEqual({ name: 'Ada' })
        })
    })

    describe('picture', () => {
        it.each(['https://img.acme.example/ada.png?size=64#top', 'https://img.acme.example', 'HTTPS://img.acme.example/ada.png'])(
            'keeps the https URL %s as given',
            (picture) => {
                expect(cleanProfile({ ...FULL, picture }).picture).toBe(picture)
            },
        )

        it.each([
            'http://img.acme.example/ada.png',
            'javascript:alert(1)',
            'data:image/png;base64,iVBORw0KGgo=',
            'ftp://img.acme.example/ada.png',
            '//img.acme.example/ada.png',
            '/ada.png',
            'img.acme.example/ada.png',
            'not a url',
            '',
            'https://',
        ])('drops %j, which is not an https URL', (picture) => {
            expect(cleanProfile({ ...FULL, picture })).not.toHaveProperty('picture')
        })

        // The URL parser strips these, so the string as written is not the URL it parses to
        it.each([
            ' https://img.acme.example/ada.png',
            'https://img.acme.example/ada.png\n',
            'https://img.acme\t.example/ada.png',
            '\x00https://img.acme.example/ada.png',
        ])('drops %j, which holds whitespace or a control character', (picture) => {
            expect(cleanProfile({ ...FULL, picture })).not.toHaveProperty('picture')
        })

        // The URL parser reads a backslash as a slash in https URLs, and C1 controls include line breaks such as NEL
        it.each([
            'https:\\\\img.acme.example\\ada.png',
            'https://img.acme.example\\ada.png',
            'https://img.acme.example/ada\\.png',
            '\u0080https://img.acme.example/ada.png',
            'https://img.acme.example/ada.png\u0085',
            'https://img.acme.example/\u009f.png',
        ])('drops %j, which holds a backslash or a C1 control character', (picture) => {
            expect(cleanProfile({ ...FULL, picture })).not.toHaveProperty('picture')
        })

        // Userinfo makes the string read as one host while it points at another
        it.each([
            'https://img.acme.example@evil.example/ada.png',
            'https://user:pass@img.acme.example/ada.png',
            'https://:pass@img.acme.example/ada.png',
            'https://user@img.acme.example/ada.png',
            'https://@img.acme.example/ada.png',
            'https:img.acme.example@evil.example/ada.png',
        ])('drops %j, which carries userinfo', (picture) => {
            expect(cleanProfile({ ...FULL, picture })).not.toHaveProperty('picture')
        })

        it('keeps an @ after the host', () => {
            const picture = 'https://img.acme.example/@ada/avatar.png?by=ada@acme.example'
            expect(cleanProfile({ ...FULL, picture }).picture).toBe(picture)
        })

        it('keeps characters past the C1 range', () => {
            const picture = 'https://img.acme.example/\u00a0caf\u00e9.png'
            expect(cleanProfile({ ...FULL, picture }).picture).toBe(picture)
        })

        it('keeps a picture without any verified flag', () => {
            expect(cleanProfile({ picture: 'https://img.acme.example/ada.png', emailVerified: false, phoneVerified: false })).toEqual({
                picture: 'https://img.acme.example/ada.png',
            })
        })
    })
})
