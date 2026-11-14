// Webhook deliveries for tests. The Clerk fixtures under test/fixtures/clerk are signed with CLERK_SECRET, and the
// Casdoor fixtures under test/fixtures/casdoor carry CASDOOR_SECRET as their bearer.

// Cases edit payloads into any shape
export type Doc = Record<string, any>

export const CLERK_SECRET = 'whsec_AAYNcW2hb0e2aiEl7L6vKXezC1nx39eQ'
export const CASDOOR_SECRET = 'test-casdoor-webhook-secret'
// Within Svix's 300 s tolerance of every Clerk fixture's timestamp
export const CLERK_NOW_MS = 1_794_608_380_000

export const WEBHOOK_URL = 'https://id.acme.example/webhooks/'

// What an IdP sends: headers and the raw body
export interface Delivery {
    headers: Record<string, string>
    body: string
}

// Casdoor fixtures hold the record as JSON, so it reads and edits as an object; its `object` member stays a string
export interface CasdoorFixture {
    headers: Record<string, string>
    body: object
}

export function casdoorDelivery(fixture: CasdoorFixture): Delivery {
    return { headers: fixture.headers, body: JSON.stringify(fixture.body) }
}

// A header set to null is left out
export function deliveryRequest(source: string, delivery: Delivery, headers: Record<string, string | null> = {}): Request {
    const merged = new Headers(delivery.headers)
    for (const [name, value] of Object.entries(headers)) {
        if (value === null) merged.delete(name)
        else merged.set(name, value)
    }
    return new Request(`${WEBHOOK_URL}${source}`, { method: 'POST', headers: merged, body: delivery.body })
}

// Svix's v1 signature: HMAC-SHA256 over `${id}.${timestamp}.${body}`, keyed by the base64 part of the secret
export async function svixSignature(secret: string, id: string, timestamp: string, body: string): Promise<string> {
    const key = await crypto.subtle.importKey('raw', fromBase64(secret.replace(/^whsec_/, '')), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
    const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${id}.${timestamp}.${body}`))
    return `v1,${toBase64(new Uint8Array(mac))}`
}

export interface ClerkEdit {
    event?: (event: Doc) => void
    id?: string
    timestamp?: string
    secret?: string
}

// The delivery with its event, svix-id or timestamp changed, signed again as Svix would
export async function resignClerk(fixture: Delivery, edit: ClerkEdit = {}): Promise<Delivery> {
    let body = fixture.body
    if (edit.event) {
        const event = JSON.parse(body) as Doc
        edit.event(event)
        body = JSON.stringify(event)
    }
    const id = edit.id ?? fixture.headers['Svix-Id']!
    const timestamp = edit.timestamp ?? fixture.headers['Svix-Timestamp']!
    const signature = await svixSignature(edit.secret ?? CLERK_SECRET, id, timestamp, body)
    return { headers: { ...fixture.headers, 'Svix-Id': id, 'Svix-Timestamp': timestamp, 'Svix-Signature': signature }, body }
}

export interface CasdoorEdit {
    record?: (record: Doc) => void
    // The record's object member, parsed and serialized again after the edit
    object?: (object: Doc) => void
}

export function editCasdoor(fixture: CasdoorFixture, edit: CasdoorEdit): CasdoorFixture {
    const record = structuredClone(fixture.body) as Doc
    if (edit.object) {
        const object = JSON.parse(record.object) as Doc
        edit.object(object)
        record.object = JSON.stringify(object)
    }
    edit.record?.(record)
    return { headers: fixture.headers, body: record }
}

function toBase64(bytes: Uint8Array): string {
    let binary = ''
    for (const byte of bytes) binary += String.fromCharCode(byte)
    return btoa(binary)
}

function fromBase64(text: string): Uint8Array<ArrayBuffer> {
    return Uint8Array.from(atob(text), (char) => char.charCodeAt(0))
}
