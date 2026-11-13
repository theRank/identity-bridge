import type { Profile, RawProfile } from './types'

const E164 = /^\+[1-9]\d{6,14}$/
// The URL parser strips these silently, so a raw string holding them is not the URL it parses to
const SPACE_OR_CONTROL = /[\x00-\x20\x7f]/

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
    if (SPACE_OR_CONTROL.test(value)) return false
    try {
        return new URL(value).protocol === 'https:'
    } catch {
        return false
    }
}
