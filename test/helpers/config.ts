// Each call returns a fresh object, so a test can change it before serializing

export function clerkConfig() {
    return {
        issuer: 'https://id.acme.example',
        region: 'us',
        tokenTtlSeconds: 900,
        idps: {
            'clerk-acme': {
                issuer: 'https://clerk.acme.example',
                jwksUri: 'https://clerk.acme.example/.well-known/jwks.json',
                algorithms: ['RS256'],
                maxTokenAgeSeconds: 900,
                clockToleranceSeconds: 60,
                claims: { uid: 'uid', email: 'email', emailVerified: true, name: 'name', picture: 'picture' },
            },
        },
        products: {
            acme: {
                idps: [{ idp: 'clerk-acme' }],
                allowedOrigins: ['https://acme.example'],
                events: { url: 'https://api.acme.example/identity/events' },
            },
        },
        webhookSources: {
            'clerk-acme': { type: 'clerk', idp: 'clerk-acme', uidField: 'external_id', products: ['acme'] },
        },
    }
}

export function casdoorConfig() {
    return {
        issuer: 'https://id.cn.acme.example',
        region: 'cn',
        idps: {
            casdoor: {
                issuer: 'https://casdoor.example',
                jwksUri: 'https://casdoor.example/.well-known/jwks',
                algorithms: ['RS256'],
                requiredClaims: { tokenType: 'access-token' },
                claims: { uid: 'uid', emailVerified: 'emailVerified', name: 'displayName', picture: 'avatar' },
            },
        },
        products: {
            acme: {
                idps: [{ idp: 'casdoor', clientIds: ['acme-web-client', 'acme-app-client', 'acme-mini-program-client'] }],
                allowedOrigins: ['https://cn.acme.example'],
                events: { url: 'https://api.cn.acme.example/identity/events' },
            },
            globex: {
                idps: [{ idp: 'casdoor', clientIds: ['globex-web-client'] }],
            },
        },
        webhookSources: {
            'casdoor-acme': { type: 'casdoor', idp: 'casdoor', organization: 'acme', uidField: 'uid', products: ['acme'] },
        },
    }
}

export const clerkConfigJson = JSON.stringify(clerkConfig())
export const casdoorConfigJson = JSON.stringify(casdoorConfig())
