export declare function getSecretVaultPath(): string;
interface SecretBundle {
    sessionSecret: string;
    credentialKeyHex: string;
    csrfSecret: string;
}
/**
 * Loads secrets from environment variables or persists auto-generated 256-bit
 * secrets in `.tgvpanel-secret` (mode 0600, git-ignored) so sessions and encrypted
 * credentials survive restarts without hardcoding secrets in source code.
 * Automatically migrates legacy `.hkvm-secret` -> `.tgvpanel-secret` if present.
 */
export declare function getSecretBundle(): SecretBundle;
/**
 * Encrypts sensitive credentials (root passwords, SSH passwords, node keys, 2FA secrets)
 * using AES-256-GCM with random 96-bit IV and 128-bit authentication tag.
 */
export declare function encryptSecret(plaintext: string | null | undefined): string;
/**
 * Decrypts AES-256-GCM credentials. Gracefully returns legacy plaintext values
 * during database migration before they are re-encrypted.
 */
export declare function decryptSecret(stored: string | null | undefined): string;
export declare function isEncryptedSecret(val: string | null | undefined): boolean;
/**
 * Generates a cryptographically strong password without shell-breaking characters.
 */
export declare function generateStrongPassword(length?: number): string;
/**
 * Generates a prefixed API key and its SHA-256 storage hash (never store raw API keys).
 */
export declare function generateApiKeyPair(prefix?: string): {
    rawKey: string;
    keyPrefix: string;
    keyHash: string;
};
export declare function hashApiKey(rawKey: string): string;
export declare function timingSafeEqualStr(a: string, b: string): boolean;
export interface SignedAgentHeaders {
    'X-HKVM-Node-Id': string;
    'X-API-Key': string;
    'X-HKVM-Timestamp': string;
    'X-HKVM-Nonce': string;
    'X-HKVM-Signature': string;
}
export declare function signAgentRequest(params: {
    nodeId: string | number;
    apiKey: string;
    hmacSecret: string;
    method: string;
    pathWithQuery: string;
    bodyBuffer?: Buffer | string;
}): SignedAgentHeaders;
export declare function verifyAgentRequestSignature(params: {
    hmacSecret: string;
    method: string;
    pathWithQuery: string;
    timestampSec: number;
    nonce: string;
    rawBody: Buffer | string;
    signatureHex: string;
    maxSkewSec?: number;
}): boolean;
export declare function base32Encode(buf: Buffer): string;
export declare function base32Decode(encoded: string): Buffer;
export declare function generateTotpSecret(): string;
export declare function computeTotpCode(secretBase32: string, stepOffset?: number, period?: number): string;
export declare function verifyTotpCode(secretBase32: string, code: string, windowSteps?: number): boolean;
export declare function generateTotpQrDataUrl(username: string, secretBase32: string, issuer?: string): Promise<{
    otpauthUrl: string;
    qrDataUrl: string;
}>;
export declare function generateCsrfToken(sessionId: string): string;
export declare function verifyCsrfToken(sessionId: string, token: string | undefined): boolean;
export {};
