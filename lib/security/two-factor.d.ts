/**
 * Two-factor authentication helpers: recovery codes and replay protection.
 *
 * The TOTP primitives already live in crypto-vault. What was missing was a way
 * back in when the phone is lost, and protection against a code being replayed
 * inside its own validity window. Both live here so the routes stay thin.
 */
import { generateStrongPassword } from './crypto-vault';
export declare const RECOVERY_CODE_COUNT = 10;
export interface DatabaseLike {
    run(sql: string, params?: any[]): Promise<any>;
    get<T = any>(sql: string, params?: any[]): Promise<T | undefined>;
    all<T = any>(sql: string, params?: any[]): Promise<T[]>;
}
export declare function generateRecoveryCode(): string;
/** Recovery codes are low-entropy, so hash them rather than storing plaintext. */
export declare function hashRecoveryCode(code: string): string;
/**
 * Replace every recovery code for a user with a fresh set.
 * Old codes are destroyed, not disabled, so a leaked sheet cannot be reused.
 */
export declare function regenerateRecoveryCodes(db: DatabaseLike, userId: number): Promise<string[]>;
/**
 * Consume a recovery code. Returns true only on the first successful use;
 * the row is marked used so a screenshot of the sheet is not a permanent key.
 */
export declare function consumeRecoveryCode(db: DatabaseLike, userId: number, code: string): Promise<boolean>;
export declare function countUnusedRecoveryCodes(db: DatabaseLike, userId: number): Promise<number>;
/** Which 30-second window a code belongs to; used for replay rejection. */
export declare function currentTotpStep(period?: number): number;
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
export declare function matchTotpStep(secretBase32: string, code: string, period?: number, windowSteps?: number): number | null;
/**
 * Full verification for a login: checks the code and enforces that its step has
 * not been used before. Persists the accepted step on success.
 */
export declare function verifyTotpForLogin(db: DatabaseLike, userId: number, secretBase32: string, code: string, period?: number): Promise<{
    ok: true;
    usedRecoveryCode: false;
} | {
    ok: false;
    reason: string;
}>;
/** Human-readable list of what 2FA state a user is in. */
export declare function describeTwoFactorState(db: DatabaseLike, userId: number): Promise<{
    enabled: boolean;
    recoveryCodesRemaining: number;
    hint: string | null;
}>;
/**
 * Admin escape hatch. Clears 2FA for a user who lost both their phone and
 * their recovery codes. Deliberately a separate function so it is obvious at
 * every call site that privileged state is being reset.
 */
export declare function resetTwoFactorForUser(db: DatabaseLike, userId: number): Promise<void>;
/** Used by the setup UI to show the code the user should expect right now. */
export declare function debugCurrentCode(secretBase32: string): string;
export { generateStrongPassword };
