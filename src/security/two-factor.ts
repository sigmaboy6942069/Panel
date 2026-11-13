/**
 * Two-factor authentication helpers: recovery codes and replay protection.
 *
 * The TOTP primitives already live in crypto-vault. What was missing was a way
 * back in when the phone is lost, and protection against a code being replayed
 * inside its own validity window. Both live here so the routes stay thin.
 */

import crypto from 'crypto';
import {
  computeTotpCode,
  verifyTotpCode,
  generateStrongPassword,
} from './crypto-vault';

export const RECOVERY_CODE_COUNT = 10;
/** Grouped as xxxx-xxxx for legibility when read off paper. */
const RECOVERY_ALPHABET = 'abcdefghijkmnpqrstuvwxyz23456789';

export interface DatabaseLike {
  run(sql: string, params?: any[]): Promise<any>;
  get<T = any>(sql: string, params?: any[]): Promise<T | undefined>;
  all<T = any>(sql: string, params?: any[]): Promise<T[]>;
}

export function generateRecoveryCode(): string {
  const bytes = crypto.randomBytes(8);
  let out = '';
  for (let i = 0; i < 8; i++) {
    out += RECOVERY_ALPHABET[bytes[i] % RECOVERY_ALPHABET.length];
  }
  return `${out.slice(0, 4)}-${out.slice(4)}`;
}

/** Recovery codes are low-entropy, so hash them rather than storing plaintext. */
export function hashRecoveryCode(code: string): string {
  const normalized = String(code || '').trim().toLowerCase().replace(/[^a-z0-9]/g, '');
  return crypto.createHash('sha256').update(normalized).digest('hex');
}

/**
 * Replace every recovery code for a user with a fresh set.
 * Old codes are destroyed, not disabled, so a leaked sheet cannot be reused.
 */
export async function regenerateRecoveryCodes(
  db: DatabaseLike,
  userId: number
): Promise<string[]> {
  await db.run(`DELETE FROM two_factor_recovery_codes WHERE user_id = ?`, [userId]);
  const codes: string[] = [];
  for (let i = 0; i < RECOVERY_CODE_COUNT; i++) {
    const code = generateRecoveryCode();
    codes.push(code);
    await db.run(
      `INSERT INTO two_factor_recovery_codes (user_id, code_hash) VALUES (?, ?)`,
      [userId, hashRecoveryCode(code)]
    );
  }
  return codes;
}

/**
 * Consume a recovery code. Returns true only on the first successful use;
 * the row is marked used so a screenshot of the sheet is not a permanent key.
 */
export async function consumeRecoveryCode(
  db: DatabaseLike,
  userId: number,
  code: string
): Promise<boolean> {
  const hash = hashRecoveryCode(code);
  if (!hash) return false;
  const row = await db.get<{ id: number }>(
    `SELECT id FROM two_factor_recovery_codes
     WHERE user_id = ? AND code_hash = ? AND used_at IS NULL`,
    [userId, hash]
  );
  if (!row) return false;
  const res = await db.run(
    `UPDATE two_factor_recovery_codes SET used_at = CURRENT_TIMESTAMP
     WHERE id = ? AND used_at IS NULL`,
    [row.id]
  );
  // If another request consumed it first, changes === 0 and this one fails.
  const changes = (res as any)?.changes;
  return changes === undefined ? true : Number(changes) > 0;
}

export async function countUnusedRecoveryCodes(
  db: DatabaseLike,
  userId: number
): Promise<number> {
  const row = await db.get<{ n: number }>(
    `SELECT COUNT(*) AS n FROM two_factor_recovery_codes
     WHERE user_id = ? AND used_at IS NULL`,
    [userId]
  );
  return Number(row?.n || 0);
}

/** Which 30-second window a code belongs to; used for replay rejection. */
export function currentTotpStep(period = 30): number {
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
export function matchTotpStep(
  secretBase32: string,
  code: string,
  period = 30,
  windowSteps = 1
): number | null {
  if (!verifyTotpCode(secretBase32, code, windowSteps)) return null;
  const now = currentTotpStep(period);
  for (let offset = -windowSteps; offset <= windowSteps; offset++) {
    if (computeTotpCode(secretBase32, offset, period) === String(code).trim()) {
      return now + offset;
    }
  }
  return null;
}

/**
 * Full verification for a login: checks the code and enforces that its step has
 * not been used before. Persists the accepted step on success.
 */
export async function verifyTotpForLogin(
  db: DatabaseLike,
  userId: number,
  secretBase32: string,
  code: string,
  period = 30
): Promise<{ ok: true; usedRecoveryCode: false } | { ok: false; reason: string }> {
  const normalized = String(code || '').trim();

  // Recovery codes are longer than 6 digits and contain a dash.
  if (normalized.replace(/[^a-z0-9]/gi, '').length > 6) {
    const consumed = await consumeRecoveryCode(db, userId, normalized);
    if (!consumed) return { ok: false, reason: 'That recovery code is not valid or has already been used.' };
    return { ok: true, usedRecoveryCode: false };
  }

  const step = matchTotpStep(secretBase32, normalized, period);
  if (step === null) return { ok: false, reason: 'Invalid 6-digit verification code.' };

  const row = await db.get<{ two_factor_last_step: number | null }>(
    `SELECT two_factor_last_step FROM users WHERE id = ?`,
    [userId]
  );
  const lastStep = row?.two_factor_last_step;
  if (lastStep !== null && lastStep !== undefined && step <= Number(lastStep)) {
    return { ok: false, reason: 'This code has already been used. Wait for the next one.' };
  }

  await db.run(`UPDATE users SET two_factor_last_step = ? WHERE id = ?`, [step, userId]);
  return { ok: true, usedRecoveryCode: false };
}

/** Human-readable list of what 2FA state a user is in. */
export async function describeTwoFactorState(
  db: DatabaseLike,
  userId: number
): Promise<{ enabled: boolean; recoveryCodesRemaining: number; hint: string | null }> {
  const row = await db.get<{ two_factor_enabled: number; two_factor_secret_enc: string | null }>(
    `SELECT two_factor_enabled, two_factor_secret_enc FROM users WHERE id = ?`,
    [userId]
  );
  const enabled = Boolean(row?.two_factor_enabled && row?.two_factor_secret_enc);
  const remaining = enabled ? await countUnusedRecoveryCodes(db, userId) : 0;
  let hint: string | null = null;
  if (enabled && remaining === 0) {
    hint = 'You have no recovery codes left. Generate a new set before you lose access.';
  } else if (enabled && remaining <= 2) {
    hint = `Only ${remaining} recovery code${remaining === 1 ? '' : 's'} left.`;
  }
  return { enabled, recoveryCodesRemaining: remaining, hint };
}

/**
 * Admin escape hatch. Clears 2FA for a user who lost both their phone and
 * their recovery codes. Deliberately a separate function so it is obvious at
 * every call site that privileged state is being reset.
 */
export async function resetTwoFactorForUser(
  db: DatabaseLike,
  userId: number
): Promise<void> {
  await db.run(
    `UPDATE users SET two_factor_enabled = 0, two_factor_secret_enc = NULL,
       two_factor_last_step = NULL WHERE id = ?`,
    [userId]
  );
  await db.run(`DELETE FROM two_factor_recovery_codes WHERE user_id = ?`, [userId]);
}

/** Used by the setup UI to show the code the user should expect right now. */
export function debugCurrentCode(secretBase32: string): string {
  return computeTotpCode(secretBase32, 0);
}

export { generateStrongPassword };
