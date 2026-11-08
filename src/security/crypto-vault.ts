import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import QRCode from 'qrcode';

function resolveSecretFilePath(): string {
  return process.env.TGVPANEL_SECRET_FILE || path.resolve(process.cwd(), '.tgvpanel-secret');
}

function resolveLegacySecretFilePath(): string {
  return path.join(path.dirname(resolveSecretFilePath()), '.hkvm-secret');
}

export function getSecretVaultPath(): string {
  return resolveSecretFilePath();
}

interface SecretBundle {
  sessionSecret: string;
  credentialKeyHex: string;
  csrfSecret: string;
}

let cachedSecrets: SecretBundle | null = null;

/**
 * Loads secrets from environment variables or persists auto-generated 256-bit
 * secrets in `.tgvpanel-secret` (mode 0600, git-ignored) so sessions and encrypted
 * credentials survive restarts without hardcoding secrets in source code.
 * Automatically migrates legacy `.hkvm-secret` -> `.tgvpanel-secret` if present.
 */
export function getSecretBundle(): SecretBundle {
  if (cachedSecrets) {
    return cachedSecrets;
  }

  const secretFilePath = resolveSecretFilePath();
  const legacySecretFilePath = resolveLegacySecretFilePath();

  if (!fs.existsSync(secretFilePath) && fs.existsSync(legacySecretFilePath)) {
    try {
      fs.renameSync(legacySecretFilePath, secretFilePath);
      fs.chmodSync(secretFilePath, 0o600);
    } catch {
      // Fallback to reading legacy path below if rename across fs fails
    }
  }

  let fileData: Partial<SecretBundle> = {};
  const readablePath = fs.existsSync(secretFilePath)
    ? secretFilePath
    : fs.existsSync(legacySecretFilePath)
    ? legacySecretFilePath
    : null;
  if (readablePath) {
    try {
      fileData = JSON.parse(fs.readFileSync(readablePath, 'utf8'));
    } catch {
      fileData = {};
    }
  }

  const sessionSecret =
    process.env.SESSION_SECRET ||
    fileData.sessionSecret ||
    crypto.randomBytes(32).toString('hex');

  const rawCredKey = process.env.CREDENTIAL_ENCRYPTION_KEY || fileData.credentialKeyHex;
  const credentialKeyHex =
    rawCredKey && /^[0-9a-fA-F]{64}$/.test(rawCredKey)
      ? rawCredKey
      : rawCredKey
      ? crypto.createHash('sha256').update(rawCredKey).digest('hex')
      : crypto.randomBytes(32).toString('hex');

  const csrfSecret =
    process.env.CSRF_SECRET ||
    fileData.csrfSecret ||
    crypto.randomBytes(32).toString('hex');

  cachedSecrets = { sessionSecret, credentialKeyHex, csrfSecret };

  if (!fs.existsSync(secretFilePath)) {
    try {
      fs.writeFileSync(secretFilePath, JSON.stringify(cachedSecrets, null, 2), {
        mode: 0o600,
      });
    } catch {
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
export function encryptSecret(plaintext: string | null | undefined): string {
  if (!plaintext) return '';
  if (plaintext.startsWith(ENC_PREFIX)) return plaintext;

  const key = Buffer.from(getSecretBundle().credentialKeyHex, 'hex');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${ENC_PREFIX}${iv.toString('base64')}:${tag.toString('base64')}:${encrypted.toString('base64')}`;
}

/**
 * Decrypts AES-256-GCM credentials. Gracefully returns legacy plaintext values
 * during database migration before they are re-encrypted.
 */
export function decryptSecret(stored: string | null | undefined): string {
  if (!stored) return '';
  if (!stored.startsWith(ENC_PREFIX)) return stored;

  try {
    const payload = stored.slice(ENC_PREFIX.length);
    const [ivB64, tagB64, dataB64] = payload.split(':');
    if (!ivB64 || !tagB64 || dataB64 === undefined) return '';
    const key = Buffer.from(getSecretBundle().credentialKeyHex, 'hex');
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      key,
      Buffer.from(ivB64, 'base64')
    );
    decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(dataB64, 'base64')),
      decipher.final(),
    ]);
    return decrypted.toString('utf8');
  } catch {
    return '';
  }
}

export function isEncryptedSecret(val: string | null | undefined): boolean {
  return Boolean(val && val.startsWith(ENC_PREFIX));
}

/**
 * Generates a cryptographically strong password without shell-breaking characters.
 */
export function generateStrongPassword(length = 20): string {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#%^&*-_=+';
  const bytes = crypto.randomBytes(length);
  let out = '';
  for (let i = 0; i < length; i++) {
    out += alphabet[bytes[i] % alphabet.length];
  }
  return out;
}

/**
 * Generates a prefixed API key and its SHA-256 storage hash (never store raw API keys).
 */
export function generateApiKeyPair(prefix = 'hkvm'): {
  rawKey: string;
  keyPrefix: string;
  keyHash: string;
} {
  const token = crypto.randomBytes(32).toString('hex');
  const rawKey = `${prefix}_${token}`;
  const keyPrefix = rawKey.slice(0, 13);
  const keyHash = hashApiKey(rawKey);
  return { rawKey, keyPrefix, keyHash };
}

export function hashApiKey(rawKey: string): string {
  return crypto.createHash('sha256').update(rawKey).digest('hex');
}

export function timingSafeEqualStr(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

// ============= NODE AGENT REQUEST SIGNING & REPLAY PROTECTION =============

export interface SignedAgentHeaders {
  'X-HKVM-Node-Id': string;
  'X-API-Key': string;
  'X-HKVM-Timestamp': string;
  'X-HKVM-Nonce': string;
  'X-HKVM-Signature': string;
}

export function signAgentRequest(params: {
  nodeId: string | number;
  apiKey: string;
  hmacSecret: string;
  method: string;
  pathWithQuery: string;
  bodyBuffer?: Buffer | string;
}): SignedAgentHeaders {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const nonce = crypto.randomBytes(16).toString('hex');
  const rawBody =
    params.bodyBuffer === undefined
      ? Buffer.alloc(0)
      : Buffer.isBuffer(params.bodyBuffer)
      ? params.bodyBuffer
      : Buffer.from(params.bodyBuffer, 'utf8');
  const bodyHash = crypto.createHash('sha256').update(rawBody).digest('hex');
  const canonical = `${timestamp}.${nonce}.${params.method.toUpperCase()}.${params.pathWithQuery}.${bodyHash}`;
  const signature = crypto
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

export function verifyAgentRequestSignature(params: {
  hmacSecret: string;
  method: string;
  pathWithQuery: string;
  timestampSec: number;
  nonce: string;
  rawBody: Buffer | string;
  signatureHex: string;
  maxSkewSec?: number;
}): boolean {
  const maxSkew = params.maxSkewSec ?? 300;
  const nowSec = Math.floor(Date.now() / 1000);
  if (!Number.isFinite(params.timestampSec) || Math.abs(nowSec - params.timestampSec) > maxSkew) {
    return false;
  }
  const bodyBuf = Buffer.isBuffer(params.rawBody)
    ? params.rawBody
    : Buffer.from(params.rawBody || '', 'utf8');
  const bodyHash = crypto.createHash('sha256').update(bodyBuf).digest('hex');
  const canonical = `${params.timestampSec}.${params.nonce}.${params.method.toUpperCase()}.${params.pathWithQuery}.${bodyHash}`;
  const expected = crypto
    .createHmac('sha256', params.hmacSecret)
    .update(canonical)
    .digest('hex');
  return timingSafeEqualStr(expected, params.signatureHex);
}

// ============= RFC 6238 TOTP TWO-FACTOR AUTHENTICATION =============

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(buf: Buffer): string {
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

export function base32Decode(encoded: string): Buffer {
  const cleaned = encoded.toUpperCase().replace(/=+$/, '').replace(/\s+/g, '');
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (const ch of cleaned) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

export function generateTotpSecret(): string {
  return base32Encode(crypto.randomBytes(20));
}

export function computeTotpCode(secretBase32: string, stepOffset = 0, period = 30): string {
  const key = base32Decode(secretBase32);
  const counter = Math.floor(Date.now() / 1000 / period) + stepOffset;
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(BigInt(counter));

  const hmac = crypto.createHmac('sha1', key).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return (binary % 1_000_000).toString().padStart(6, '0');
}

export function verifyTotpCode(secretBase32: string, code: string, windowSteps = 1): boolean {
  const normalized = String(code || '').trim();
  if (!/^\d{6}$/.test(normalized)) return false;
  for (let step = -windowSteps; step <= windowSteps; step++) {
    if (timingSafeEqualStr(computeTotpCode(secretBase32, step), normalized)) {
      return true;
    }
  }
  return false;
}

export async function generateTotpQrDataUrl(
  username: string,
  secretBase32: string,
  issuer = 'TGVPANEL'
): Promise<{ otpauthUrl: string; qrDataUrl: string }> {
  const label = encodeURIComponent(`${issuer}:${username}`);
  const otpauthUrl = `otpauth://totp/${label}?secret=${encodeURIComponent(
    secretBase32
  )}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
  const qrDataUrl = await QRCode.toDataURL(otpauthUrl, { width: 220, margin: 1 });
  return { otpauthUrl, qrDataUrl };
}

// ============= CSRF TOKEN HELPERS =============

export function generateCsrfToken(sessionId: string): string {
  const nonce = crypto.randomBytes(12).toString('hex');
  const sig = crypto
    .createHmac('sha256', getSecretBundle().csrfSecret)
    .update(`${sessionId}:${nonce}`)
    .digest('hex');
  return `${nonce}.${sig}`;
}

export function verifyCsrfToken(sessionId: string, token: string | undefined): boolean {
  if (!token || !token.includes('.')) return false;
  const [nonce, sig] = token.split('.', 2);
  if (!nonce || !sig) return false;
  const expected = crypto
    .createHmac('sha256', getSecretBundle().csrfSecret)
    .update(`${sessionId}:${nonce}`)
    .digest('hex');
  return timingSafeEqualStr(sig, expected);
}
