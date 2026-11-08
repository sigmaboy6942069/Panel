"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.UnifiedDatabase = void 0;
exports.resolveAndMigrateDatabasePath = resolveAndMigrateDatabasePath;
exports.registerUnifiedDatabase = registerUnifiedDatabase;
exports.getUnifiedDatabase = getUnifiedDatabase;
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
/**
 * Resolves the unified TGVPANEL SQLite path (`<dbDir>/tgvpanel.db` unless `explicitPath` is passed)
 * and automatically migrates any legacy `<dbDir>/hkvm.db` (+ `-wal` / `-shm`) on disk with zero data loss.
 */
function resolveAndMigrateDatabasePath(dbDir, explicitPath) {
    fs_1.default.mkdirSync(dbDir, { recursive: true, mode: 0o755 });
    if (explicitPath && explicitPath.trim().length > 0) {
        return explicitPath.trim();
    }
    const targetPath = path_1.default.join(dbDir, 'tgvpanel.db');
    const legacyPath = path_1.default.join(dbDir, 'hkvm.db');
    if (!fs_1.default.existsSync(legacyPath)) {
        return targetPath;
    }
    try {
        const backupDir = path_1.default.join(dbDir, 'backups');
        fs_1.default.mkdirSync(backupDir, { recursive: true });
        const ts = new Date().toISOString().replace(/[:.]/g, '-');
        if (!fs_1.default.existsSync(targetPath)) {
            // Pure rename: hkvm.db (+ -wal/-shm) -> tgvpanel.db (+ -wal/-shm)
            fs_1.default.copyFileSync(legacyPath, path_1.default.join(backupDir, `tgvpanel_migrated_from_hkvm_${ts}.db`));
            fs_1.default.renameSync(legacyPath, targetPath);
            for (const suffix of ['-wal', '-shm', '-journal']) {
                if (fs_1.default.existsSync(legacyPath + suffix)) {
                    fs_1.default.renameSync(legacyPath + suffix, targetPath + suffix);
                }
            }
        }
        else if (!fs_1.default.existsSync(targetPath + '-wal')) {
            // Both exist right after git checkout of baseline tgvpanel.db while live hkvm.db remained on disk:
            // Preserve both in backups and promote live hkvm.db (+ -wal/-shm) to tgvpanel.db!
            fs_1.default.copyFileSync(targetPath, path_1.default.join(backupDir, `tgvpanel_repo_baseline_${ts}.db`));
            fs_1.default.copyFileSync(legacyPath, path_1.default.join(backupDir, `tgvpanel_migrated_from_hkvm_${ts}.db`));
            fs_1.default.renameSync(legacyPath, targetPath);
            for (const suffix of ['-wal', '-shm', '-journal']) {
                if (fs_1.default.existsSync(targetPath + suffix)) {
                    try {
                        fs_1.default.unlinkSync(targetPath + suffix);
                    }
                    catch { /* ignore */ }
                }
                if (fs_1.default.existsSync(legacyPath + suffix)) {
                    fs_1.default.renameSync(legacyPath + suffix, targetPath + suffix);
                }
            }
        }
    }
    catch (err) {
        console.warn('[TGVPANEL DB File Migration Warning]:', err.message);
    }
    return targetPath;
}
class UnifiedDatabase {
    raw;
    dbPath;
    constructor(rawDb, dbPath) {
        this.raw = rawDb;
        this.dbPath = dbPath;
    }
    get(sql, params = []) {
        return new Promise((resolve, reject) => {
            this.raw.get(sql, params, (err, row) => {
                if (err)
                    reject(err);
                else
                    resolve(row);
            });
        });
    }
    all(sql, params = []) {
        return new Promise((resolve, reject) => {
            this.raw.all(sql, params, (err, rows) => {
                if (err)
                    reject(err);
                else
                    resolve((rows || []));
            });
        });
    }
    run(sql, params = []) {
        return new Promise((resolve, reject) => {
            this.raw.run(sql, params, function (err) {
                if (err)
                    reject(err);
                else
                    resolve({ lastID: this.lastID || 0, changes: this.changes || 0 });
            });
        });
    }
    exec(sql) {
        return new Promise((resolve, reject) => {
            this.raw.exec(sql, (err) => {
                if (err)
                    reject(err);
                else
                    resolve();
            });
        });
    }
    /**
     * Executes multiple statements atomically inside a SQLite transaction.
     */
    async transaction(fn) {
        await this.run('BEGIN IMMEDIATE TRANSACTION');
        try {
            const result = await fn();
            await this.run('COMMIT');
            return result;
        }
        catch (err) {
            try {
                await this.run('ROLLBACK');
            }
            catch {
                // Ignore rollback secondary error
            }
            throw err;
        }
    }
    /**
     * Creates an automatic timestamped backup of data/tgvpanel.db before running migrations.
     */
    async createBackup(label = 'auto') {
        const dir = path_1.default.join(path_1.default.dirname(this.dbPath), 'backups');
        fs_1.default.mkdirSync(dir, { recursive: true });
        const ts = new Date().toISOString().replace(/[:.]/g, '-');
        const safeLabel = label.replace(/[^a-zA-Z0-9_-]/g, '_');
        const backupPath = path_1.default.join(dir, `tgvpanel_${safeLabel}_${ts}.db`);
        // Checkpoint WAL first so the copy is self-contained, then use VACUUM INTO if supported
        try {
            await this.run('PRAGMA wal_checkpoint(PASSIVE)');
            const escaped = backupPath.replace(/'/g, "''");
            await this.run(`VACUUM INTO '${escaped}'`);
        }
        catch {
            fs_1.default.copyFileSync(this.dbPath, backupPath);
        }
        const stat = fs_1.default.statSync(backupPath);
        return { backupPath, sizeBytes: stat.size };
    }
    async logActivity(params) {
        try {
            const detailsStr = params.details === null || params.details === undefined
                ? null
                : typeof params.details === 'string'
                    ? params.details
                    : JSON.stringify(params.details);
            await this.run(`INSERT INTO activity_logs (user_id, action, resource_type, resource_id, details, ip_address, user_agent, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))`, [
                params.userId ?? null,
                params.action,
                params.resourceType ?? null,
                params.resourceId !== undefined && params.resourceId !== null
                    ? String(params.resourceId)
                    : null,
                detailsStr,
                params.ipAddress ?? null,
                params.userAgent ?? null,
            ]);
        }
        catch {
            // Never crash caller if audit table is mid-initialization
        }
    }
    close() {
        return new Promise((resolve, reject) => {
            this.raw.close((err) => {
                if (err)
                    reject(err);
                else
                    resolve();
            });
        });
    }
}
exports.UnifiedDatabase = UnifiedDatabase;
let singletonDb = null;
function registerUnifiedDatabase(rawDb, dbPath) {
    singletonDb = new UnifiedDatabase(rawDb, dbPath);
    return singletonDb;
}
function getUnifiedDatabase() {
    if (!singletonDb) {
        throw new Error('UnifiedDatabase has not been initialized yet');
    }
    return singletonDb;
}
