"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getSecretVaultPath = getSecretVaultPath;
exports.getSecretBundle = getSecretBundle;
exports.encryptSecret = encryptSecret;
exports.decryptSecret = decryptSecret;
exports.isEncryptedSecret = isEncryptedSecret;
exports.generateStrongPassword = generateStrongPassword;
exports.generateApiKeyPair = generateApiKeyPair;
exports.hashApiKey = hashApiKey;
exports.timingSafeEqualStr = timingSafeEqualStr;
exports.signAgentRequest = signAgentRequest;
exports.verifyAgentRequestSignature = verifyAgentRequestSignature;
exports.base32Encode = base32Encode;
exports.base32Decode = base32Decode;
exports.generateTotpSecret = generateTotpSecret;
exports.computeTotpCode = computeTotpCode;
exports.verifyTotpCode = verifyTotpCode;
exports.generateTotpQrDataUrl = generateTotpQrDataUrl;
exports.generateCsrfToken = generateCsrfToken;
exports.verifyCsrfToken = verifyCsrfToken;
const crypto_1 = __importDefault(require("crypto"));
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const qrcode_1 = __importDefault(require("qrcode"));
function resolveSecretFilePath() {
    return process.env.TGVPANEL_SECRET_FILE || path_1.default.resolve(process.cwd(), '.tgvpanel-secret');
}
function resolveLegacySecretFilePath() {
    return path_1.default.join(path_1.default.dirname(resolveSecretFilePath()), '.hkvm-secret');
}
function getSecretVaultPath() {
    return resolveSecretFilePath();
}
let cachedSecrets = null;
/**
 * Loads secrets from environment variables or persists auto-generated 256-bit
 * secrets in `.tgvpanel-secret` (mode 0600, git-ignored) so sessions and encrypted
 * credentials survive restarts without hardcoding secrets in source code.
 * Automatically migrates legacy `.hkvm-secret` -> `.tgvpanel-secret` if present.
 */
function getSecretBundle() {
    if (cachedSecrets) {
        return cachedSecrets;
    }
    const secretFilePath = resolveSecretFilePath();
    const legacySecretFilePath = resolveLegacySecretFilePath();
    if (!fs_1.default.existsSync(secretFilePath) && fs_1.default.existsSync(legacySecretFilePath)) {
        try {
            fs_1.default.renameSync(legacySecretFilePath, secretFilePath);
            fs_1.default.chmodSync(secretFilePath, 0o600);
        }
        catch {
            // Fallback to reading legacy path below if rename across fs fails
        }
    }
    let fileData = {};
    const readablePath = fs_1.default.existsSync(secretFilePath)
        ? secretFilePath
        : fs_1.default.existsSync(legacySecretFilePath)
            ? legacySecretFilePath
            : null;
    if (readablePath) {
        try {
            fileData = JSON.parse(fs_1.default.readFileSync(readablePath, 'utf8'));
        }
        catch {
            fileData = {};
        }
    }
    const sessionSecret = process.env.SESSION_SECRET ||
        fileData.sessionSecret ||
        crypto_1.default.randomBytes(32).toString('hex');
    const rawCredKey = process.env.CREDENTIAL_ENCRYPTION_KEY || fileData.credentialKeyHex;
    const credentialKeyHex = rawCredKey && /^[0-9a-fA-F]{64}$/.test(rawCredKey)
        ? rawCredKey
        : rawCredKey
            ? crypto_1.default.createHash('sha256').update(rawCredKey).digest('hex')
            : crypto_1.default.randomBytes(32).toString('hex');
    const csrfSecret = process.env.CSRF_SECRET ||
        fileData.csrfSecret ||
        crypto_1.default.randomBytes(32).toString('hex');
    cachedSecrets = { sessionSecret, credentialKeyHex, csrfSecret };
    if (!fs_1.default.existsSync(secretFilePath)) {
        try {
            fs_1.default.writeFileSync(secretFilePath, JSON.stringify(cachedSecrets, null, 2), {
                mode: 0o600,
            });
        }
        catch {
            // Non-fatal if working directory is read-only
        }
    }
    return cachedSecrets;
}
const ENC_PREFIX = 'enc:v1:';
/**
 * Encrypts sensitive credentials (root passwords, SSH passwords, node keys, 2FA secrets)
 * using AES-256-GCM with random 96-bit IV and 128-bit authentication tag.
 */
function encryptSecret(plaintext) {
    if (!plaintext)
        return '';
    if (plaintext.startsWith(ENC_PREFIX))
        return plaintext;
    const key = Buffer.from(getSecretBundle().credentialKeyHex, 'hex');
    const iv = crypto_1.default.randomBytes(12);
    const cipher = crypto_1.default.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return `${ENC_PREFIX}${iv.toString('base64')}:${tag.toString('base64')}:${encrypted.toString('base64')}`;
}
/**
 * Decrypts AES-256-GCM credentials. Gracefully returns legacy plaintext values
 * during database migration before they are re-encrypted.
 */
function decryptSecret(stored) {
    if (!stored)
        return '';
    if (!stored.startsWith(ENC_PREFIX))
        return stored;
    try {
        const payload = stored.slice(ENC_PREFIX.length);
        const [ivB64, tagB64, dataB64] = payload.split(':');
        if (!ivB64 || !tagB64 || dataB64 === undefined)
            return '';
        const key = Buffer.from(getSecretBundle().credentialKeyHex, 'hex');
        const decipher = crypto_1.default.createDecipheriv('aes-256-gcm', key, Buffer.from(ivB64, 'base64'));
        decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
        const decrypted = Buffer.concat([
            decipher.update(Buffer.from(dataB64, 'base64')),
            decipher.final(),
        ]);
        return decrypted.toString('utf8');
    }
    catch {
        return '';
    }
}
function isEncryptedSecret(val) {
    return Boolean(val && val.startsWith(ENC_PREFIX));
}
/**
 * Generates a cryptographically strong password without shell-breaking characters.
 */
function generateStrongPassword(length = 20) {
    const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#%^&*-_=+';
    const bytes = crypto_1.default.randomBytes(length);
    let out = '';
    for (let i = 0; i < length; i++) {
        out += alphabet[bytes[i] % alphabet.length];
    }
    return out;
}
/**
 * Generates a prefixed API key and its SHA-256 storage hash (never store raw API keys).
 */
function generateApiKeyPair(prefix = 'hkvm') {
    const token = crypto_1.default.randomBytes(32).toString('hex');
    const rawKey = `${prefix}_${token}`;
    const keyPrefix = rawKey.slice(0, 13);
    const keyHash = hashApiKey(rawKey);
    return { rawKey, keyPrefix, keyHash };
}
function hashApiKey(rawKey) {
    return crypto_1.default.createHash('sha256').update(rawKey).digest('hex');
}
function timingSafeEqualStr(a, b) {
    const bufA = Buffer.from(a, 'utf8');
    const bufB = Buffer.from(b, 'utf8');
    if (bufA.length !== bufB.length)
        return false;
    return crypto_1.default.timingSafeEqual(bufA, bufB);
}
function signAgentRequest(params) {
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const nonce = crypto_1.default.randomBytes(16).toString('hex');
    const rawBody = params.bodyBuffer === undefined
        ? Buffer.alloc(0)
        : Buffer.isBuffer(params.bodyBuffer)
            ? params.bodyBuffer
            : Buffer.from(params.bodyBuffer, 'utf8');
    const bodyHash = crypto_1.default.createHash('sha256').update(rawBody).digest('hex');
    const canonical = `${timestamp}.${nonce}.${params.method.toUpperCase()}.${params.pathWithQuery}.${bodyHash}`;
    const signature = crypto_1.default
        .createHmac('sha256', params.hmacSecret)
        .update(canonical)
        .digest('hex');
    return {
        'X-HKVM-Node-Id': String(params.nodeId),
        'X-API-Key': params.apiKey,
        'X-HKVM-Timestamp': timestamp,
        'X-HKVM-Nonce': nonce,
        'X-HKVM-Signature': signature,
    };
}
function verifyAgentRequestSignature(params) {
    const maxSkew = params.maxSkewSec ?? 300;
    const nowSec = Math.floor(Date.now() / 1000);
    if (!Number.isFinite(params.timestampSec) || Math.abs(nowSec - params.timestampSec) > maxSkew) {
        return false;
    }
    const bodyBuf = Buffer.isBuffer(params.rawBody)
        ? params.rawBody
        : Buffer.from(params.rawBody || '', 'utf8');
    const bodyHash = crypto_1.default.createHash('sha256').update(bodyBuf).digest('hex');
    const canonical = `${params.timestampSec}.${params.nonce}.${params.method.toUpperCase()}.${params.pathWithQuery}.${bodyHash}`;
    const expected = crypto_1.default
        .createHmac('sha256', params.hmacSecret)
        .update(canonical)
        .digest('hex');
    return timingSafeEqualStr(expected, params.signatureHex);
}
// ============= RFC 6238 TOTP TWO-FACTOR AUTHENTICATION =============
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32Encode(buf) {
    let bits = 0;
    let value = 0;
    let output = '';
    for (let i = 0; i < buf.length; i++) {
        value = (value << 8) | buf[i];
        bits += 8;
        while (bits >= 5) {
            output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
            bits -= 5;
        }
    }
    if (bits > 0) {
        output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
    }
    return output;
}
function base32Decode(encoded) {
    const cleaned = encoded.toUpperCase().replace(/=+$/, '').replace(/\s+/g, '');
    let bits = 0;
    let value = 0;
    const bytes = [];
    for (const ch of cleaned) {
        const idx = BASE32_ALPHABET.indexOf(ch);
        if (idx === -1)
            continue;
        value = (value << 5) | idx;
        bits += 5;
        if (bits >= 8) {
            bytes.push((value >>> (bits - 8)) & 0xff);
            bits -= 8;
        }
    }
    return Buffer.from(bytes);
}
function generateTotpSecret() {
    return base32Encode(crypto_1.default.randomBytes(20));
}
function computeTotpCode(secretBase32, stepOffset = 0, period = 30) {
    const key = base32Decode(secretBase32);
    const counter = Math.floor(Date.now() / 1000 / period) + stepOffset;
    const counterBuf = Buffer.alloc(8);
    counterBuf.writeBigUInt64BE(BigInt(counter));
    const hmac = crypto_1.default.createHmac('sha1', key).update(counterBuf).digest();
    const offset = hmac[hmac.length - 1] & 0x0f;
    const binary = ((hmac[offset] & 0x7f) << 24) |
        ((hmac[offset + 1] & 0xff) << 16) |
        ((hmac[offset + 2] & 0xff) << 8) |
        (hmac[offset + 3] & 0xff);
    return (binary % 1_000_000).toString().padStart(6, '0');
}
function verifyTotpCode(secretBase32, code, windowSteps = 1) {
    const normalized = String(code || '').trim();
    if (!/^\d{6}$/.test(normalized))
        return false;
    for (let step = -windowSteps; step <= windowSteps; step++) {
        if (timingSafeEqualStr(computeTotpCode(secretBase32, step), normalized)) {
            return true;
        }
    }
    return false;
}
async function generateTotpQrDataUrl(username, secretBase32, issuer = 'TGVPANEL') {
    const label = encodeURIComponent(`${issuer}:${username}`);
    const otpauthUrl = `otpauth://totp/${label}?secret=${encodeURIComponent(secretBase32)}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
    const qrDataUrl = await qrcode_1.default.toDataURL(otpauthUrl, { width: 220, margin: 1 });
    return { otpauthUrl, qrDataUrl };
}
// ============= CSRF TOKEN HELPERS =============
function generateCsrfToken(sessionId) {
    const nonce = crypto_1.default.randomBytes(12).toString('hex');
    const sig = crypto_1.default
        .createHmac('sha256', getSecretBundle().csrfSecret)
        .update(`${sessionId}:${nonce}`)
        .digest('hex');
    return `${nonce}.${sig}`;
}
function verifyCsrfToken(sessionId, token) {
    if (!token || !token.includes('.'))
        return false;
    const [nonce, sig] = token.split('.', 2);
    if (!nonce || !sig)
        return false;
    const expected = crypto_1.default
        .createHmac('sha256', getSecretBundle().csrfSecret)
        .update(`${sessionId}:${nonce}`)
        .digest('hex');
    return timingSafeEqualStr(sig, expected);
}
