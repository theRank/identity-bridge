// A form body as URLSearchParams serializes it, built by hand because WeChat mini programs have no URLSearchParams
export function formBody(fields: [name: string, value: string][]): string {
    return fields.map(([name, value]) => `${encode(name)}=${encode(value)}`).join('&')
}

// encodeURIComponent leaves !'()~ as they are and writes a space as %20, where the form encoding escapes them and
// writes a space as +
function encode(value: string): string {
    return encodeURIComponent(value)
        .replace(/[!'()~]/g, (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`)
        .replace(/%20/g, '+')
}

export function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value)
}
