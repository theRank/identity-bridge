import { bridgeSigningKeys } from './keys'

export interface UnquotedPrivateKey {
    // SIGNING_KEYS without the quote before the private key's value: invalid JSON
    json: string
    d: string
}

// V8's JSON.parse message quotes the text around the error, here the start of the private key, so a load failure
// reason that passed the message on would leak it. It quotes nothing when the value starts with a minus sign,
// which only a number may follow, so keys are generated until one is quoted.
export async function unquotedPrivateKey(): Promise<UnquotedPrivateKey> {
    for (;;) {
        const { json, active } = await bridgeSigningKeys()
        const broken = json.replace('"d":"', '"d":')
        if (parseMessage(broken).includes(active.d!.slice(0, 6))) return { json: broken, d: active.d! }
    }
}

function parseMessage(text: string): string {
    try {
        JSON.parse(text)
        return ''
    } catch (error) {
        return (error as Error).message
    }
}

// Shorter runs could occur by chance in fixed English text; a run of six would mean the value was quoted
export function runsOf(value: string, length = 6): string[] {
    return Array.from({ length: Math.max(value.length - length + 1, 0) }, (_, index) => value.slice(index, index + length))
}
