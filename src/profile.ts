import type { Profile, RawProfile } from './types'

const E164 = /^\+[1-9]\d{6,14}$/
// The URL parser strips C0 controls and spaces silently and reads a backslash as a slash, so a raw string
// holding them is not the URL it parses to; C1 controls include line breaks such as NEL
const UNSAFE_IN_URL = /[\x00-\x20\x7f-\x9f\\]/
// Userinfo makes the string read as one host while it points at another; an empty one parses to no username
const AT_IN_AUTHORITY = /^[^/?#]*\/\/[^/?#]*@/

// Values come from tokens and payloads, so each is checked here; anything unusable is left out
export function cleanProfile(raw: RawProfile): Profile {
    const { email, phone, name, picture } = raw
    const profile: Profile = {}
    if (raw.emailVerified === true && typeof email === 'string' && email.includes('@')) profile.email = email
    if (raw.phoneVerified === true && typeof phone === 'string' && E164.test(phone)) profile.phoneNumber = phone
    const trimmed = typeof name === 'string' ? name.trim() : ''
    if (trimmed !== '') profile.name = trimmed
    if (typeof picture === 'string' && isHttpsUrl(picture)) profile.picture = picture
    return profile
}

// try rather than URL.parse, which not every edge runtime provides
function isHttpsUrl(value: string): boolean {
    if (UNSAFE_IN_URL.test(value) || AT_IN_AUTHORITY.test(value)) return false
    try {
        const url = new URL(value)
        return url.protocol === 'https:' && url.username === '' && url.password === ''
    } catch {
        return false
    }
}
