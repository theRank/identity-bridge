// Every byte is compared whatever the earlier ones held, so the time taken never tells how long a matching prefix
// is. Lengths differ at once: a length is not secret.
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.byteLength !== b.byteLength) return false
    let difference = 0
    for (let index = 0; index < a.byteLength; index++) difference |= a[index]! ^ b[index]!
    return difference === 0
}
