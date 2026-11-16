// Returns at once on a length mismatch: a length is not secret
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.byteLength !== b.byteLength) return false
    let difference = 0
    for (let index = 0; index < a.byteLength; index++) difference |= a[index]! ^ b[index]!
    return difference === 0
}
