"use strict";
/**
 * Two-factor authentication helpers: recovery codes and replay protection.
 *
 * The TOTP primitives already live in crypto-vault. What was missing was a way
 * back in when the phone is lost, and protection against a code being replayed
 * inside its own validity window. Both live here so the routes stay thin.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateStrongPassword = exports.RECOVERY_CODE_COUNT = void 0;
exports.generateRecoveryCode = generateRecoveryCode;
exports.hashRecoveryCode = hashRecoveryCode;
exports.regenerateRecoveryCodes = regenerateRecoveryCodes;
exports.consumeRecoveryCode = consumeRecoveryCode;
exports.countUnusedRecoveryCodes = countUnusedRecoveryCodes;
exports.currentTotpStep = currentTotpStep;
exports.matchTotpStep = matchTotpStep;
exports.verifyTotpForLogin = verifyTotpForLogin;
exports.describeTwoFactorState = describeTwoFactorState;
exports.resetTwoFactorForUser = resetTwoFactorForUser;
exports.debugCurrentCode = debugCurrentCode;
const crypto_1 = __importDefault(require("crypto"));
const crypto_vault_1 = require("./crypto-vault");
Object.defineProperty(exports, "generateStrongPassword", { enumerable: true, get: function () { return crypto_vault_1.generateStrongPassword; } });
exports.RECOVERY_CODE_COUNT = 10;
/** Grouped as xxxx-xxxx for legibility when read off paper. */
const RECOVERY_ALPHABET = 'abcdefghijkmnpqrstuvwxyz23456789';
function generateRecoveryCode() {
    const bytes = crypto_1.default.randomBytes(8);
    let out = '';
    for (let i = 0; i < 8; i++) {
        out += RECOVERY_ALPHABET[bytes[i] % RECOVERY_ALPHABET.length];
    }
    return `${out.slice(0, 4)}-${out.slice(4)}`;
}
/** Recovery codes are low-entropy, so hash them rather than storing plaintext. */
function hashRecoveryCode(code) {
    const normalized = String(code || '').trim().toLowerCase().replace(/[^a-z0-9]/g, '');
    return crypto_1.default.createHash('sha256').update(normalized).digest('hex');
}
/**
 * Replace every recovery code for a user with a fresh set.
 * Old codes are destroyed, not disabled, so a leaked sheet cannot be reused.
 */
async function regenerateRecoveryCodes(db, userId) {
    await db.run(`DELETE FROM two_factor_recovery_codes WHERE user_id = ?`, [userId]);
    const codes = [];
    for (let i = 0; i < exports.RECOVERY_CODE_COUNT; i++) {
        const code = generateRecoveryCode();
        codes.push(code);
        await db.run(`INSERT INTO two_factor_recovery_codes (user_id, code_hash) VALUES (?, ?)`, [userId, hashRecoveryCode(code)]);
    }
    return codes;
}
/**
 * Consume a recovery code. Returns true only on the first successful use;
 * the row is marked used so a screenshot of the sheet is not a permanent key.
 */
async function consumeRecoveryCode(db, userId, code) {
    const hash = hashRecoveryCode(code);
    if (!hash)
        return false;
    const row = await db.get(`SELECT id FROM two_factor_recovery_codes
     WHERE user_id = ? AND code_hash = ? AND used_at IS NULL`, [userId, hash]);
    if (!row)
        return false;
    const res = await db.run(`UPDATE two_factor_recovery_codes SET used_at = CURRENT_TIMESTAMP
     WHERE id = ? AND used_at IS NULL`, [row.id]);
    // If another request consumed it first, changes === 0 and this one fails.
    const changes = res?.changes;
    return changes === undefined ? true : Number(changes) > 0;
}
async function countUnusedRecoveryCodes(db, userId) {
    const row = await db.get(`SELECT COUNT(*) AS n FROM two_factor_recovery_codes
     WHERE user_id = ? AND used_at IS NULL`, [userId]);
    return Number(row?.n || 0);
}
/** Which 30-second window a code belongs to; used for replay rejection. */
function currentTotpStep(period = 30) {
    return Math.floor(Date.now() / 1000 / period);
}
/**
 * Verify a TOTP code and, on success, refuse anything at or before the last
 * accepted step.
 *
 * Without this, an attacker who shoulder-surfs a code (or replays a captured
 * request) has up to 90 seconds to use it again: the ±1 step window that
 * tolerates clock skew also accepts the same code repeatedly.
 *
 * Returns the step number that matched, or null.
 */
function matchTotpStep(secretBase32, code, period = 30, windowSteps = 1) {
    if (!(0, crypto_vault_1.verifyTotpCode)(secretBase32, code, windowSteps))
        return null;
    const now = currentTotpStep(period);
    for (let offset = -windowSteps; offset <= windowSteps; offset++) {
        if ((0, crypto_vault_1.computeTotpCode)(secretBase32, offset, period) === String(code).trim()) {
            return now + offset;
        }
    }
    return null;
}
/**
 * Full verification for a login: checks the code and enforces that its step has
 * not been used before. Persists the accepted step on success.
 */
async function verifyTotpForLogin(db, userId, secretBase32, code, period = 30) {
    const normalized = String(code || '').trim();
    // Recovery codes are longer than 6 digits and contain a dash.
    if (normalized.replace(/[^a-z0-9]/gi, '').length > 6) {
        const consumed = await consumeRecoveryCode(db, userId, normalized);
        if (!consumed)
            return { ok: false, reason: 'That recovery code is not valid or has already been used.' };
        return { ok: true, usedRecoveryCode: false };
    }
    const step = matchTotpStep(secretBase32, normalized, period);
    if (step === null)
        return { ok: false, reason: 'Invalid 6-digit verification code.' };
    const row = await db.get(`SELECT two_factor_last_step FROM users WHERE id = ?`, [userId]);
    const lastStep = row?.two_factor_last_step;
    if (lastStep !== null && lastStep !== undefined && step <= Number(lastStep)) {
        return { ok: false, reason: 'This code has already been used. Wait for the next one.' };
    }
    await db.run(`UPDATE users SET two_factor_last_step = ? WHERE id = ?`, [step, userId]);
    return { ok: true, usedRecoveryCode: false };
}
/** Human-readable list of what 2FA state a user is in. */
async function describeTwoFactorState(db, userId) {
    const row = await db.get(`SELECT two_factor_enabled, two_factor_secret_enc FROM users WHERE id = ?`, [userId]);
    const enabled = Boolean(row?.two_factor_enabled && row?.two_factor_secret_enc);
    const remaining = enabled ? await countUnusedRecoveryCodes(db, userId) : 0;
    let hint = null;
    if (enabled && remaining === 0) {
        hint = 'You have no recovery codes left. Generate a new set before you lose access.';
    }
    else if (enabled && remaining <= 2) {
        hint = `Only ${remaining} recovery code${remaining === 1 ? '' : 's'} left.`;
    }
    return { enabled, recoveryCodesRemaining: remaining, hint };
}
/**
 * Admin escape hatch. Clears 2FA for a user who lost both their phone and
 * their recovery codes. Deliberately a separate function so it is obvious at
 * every call site that privileged state is being reset.
 */
async function resetTwoFactorForUser(db, userId) {
    await db.run(`UPDATE users SET two_factor_enabled = 0, two_factor_secret_enc = NULL,
       two_factor_last_step = NULL WHERE id = ?`, [userId]);
    await db.run(`DELETE FROM two_factor_recovery_codes WHERE user_id = ?`, [userId]);
}
/** Used by the setup UI to show the code the user should expect right now. */
function debugCurrentCode(secretBase32) {
    return (0, crypto_vault_1.computeTotpCode)(secretBase32, 0);
}
