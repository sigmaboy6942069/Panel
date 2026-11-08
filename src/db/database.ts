import fs from 'fs';
import path from 'path';
import sqlite3 from 'sqlite3';

export interface RunResult {
  lastID: number;
  changes: number;
}

/**
 * Resolves the unified TGVPANEL SQLite path (`<dbDir>/tgvpanel.db` unless `explicitPath` is passed)
 * and automatically migrates any legacy `<dbDir>/hkvm.db` (+ `-wal` / `-shm`) on disk with zero data loss.
 */
export function resolveAndMigrateDatabasePath(dbDir: string, explicitPath?: string): string {
  fs.mkdirSync(dbDir, { recursive: true, mode: 0o755 });
  if (explicitPath && explicitPath.trim().length > 0) {
    return explicitPath.trim();
  }

  const targetPath = path.join(dbDir, 'tgvpanel.db');
  const legacyPath = path.join(dbDir, 'hkvm.db');

  if (!fs.existsSync(legacyPath)) {
    return targetPath;
  }

  try {
    const backupDir = path.join(dbDir, 'backups');
    fs.mkdirSync(backupDir, { recursive: true });
    const ts = new Date().toISOString().replace(/[:.]/g, '-');

    if (!fs.existsSync(targetPath)) {
      // Pure rename: hkvm.db (+ -wal/-shm) -> tgvpanel.db (+ -wal/-shm)
      fs.copyFileSync(legacyPath, path.join(backupDir, `tgvpanel_migrated_from_hkvm_${ts}.db`));
      fs.renameSync(legacyPath, targetPath);
      for (const suffix of ['-wal', '-shm', '-journal']) {
        if (fs.existsSync(legacyPath + suffix)) {
          fs.renameSync(legacyPath + suffix, targetPath + suffix);
        }
      }
    } else if (!fs.existsSync(targetPath + '-wal')) {
      // Both exist right after git checkout of baseline tgvpanel.db while live hkvm.db remained on disk:
      // Preserve both in backups and promote live hkvm.db (+ -wal/-shm) to tgvpanel.db!
      fs.copyFileSync(targetPath, path.join(backupDir, `tgvpanel_repo_baseline_${ts}.db`));
      fs.copyFileSync(legacyPath, path.join(backupDir, `tgvpanel_migrated_from_hkvm_${ts}.db`));
      fs.renameSync(legacyPath, targetPath);
      for (const suffix of ['-wal', '-shm', '-journal']) {
        if (fs.existsSync(targetPath + suffix)) {
          try { fs.unlinkSync(targetPath + suffix); } catch { /* ignore */ }
        }
        if (fs.existsSync(legacyPath + suffix)) {
          fs.renameSync(legacyPath + suffix, targetPath + suffix);
        }
      }
    }
  } catch (err) {
    console.warn('[TGVPANEL DB File Migration Warning]:', (err as Error).message);
  }

  return targetPath;
}

export class UnifiedDatabase {
  public readonly raw: sqlite3.Database;
  public readonly dbPath: string;

  constructor(rawDb: sqlite3.Database, dbPath: string) {
    this.raw = rawDb;
    this.dbPath = dbPath;
  }

  public get<T = any>(sql: string, params: any[] = []): Promise<T | undefined> {
    return new Promise((resolve, reject) => {
      this.raw.get(sql, params, (err, row) => {
        if (err) reject(err);
        else resolve(row as T | undefined);
      });
    });
  }

  public all<T = any>(sql: string, params: any[] = []): Promise<T[]> {
    return new Promise((resolve, reject) => {
      this.raw.all(sql, params, (err, rows) => {
        if (err) reject(err);
        else resolve((rows || []) as T[]);
      });
    });
  }

  public run(sql: string, params: any[] = []): Promise<RunResult> {
    return new Promise((resolve, reject) => {
      this.raw.run(sql, params, function (this: sqlite3.RunResult, err: Error | null) {
        if (err) reject(err);
        else resolve({ lastID: this.lastID || 0, changes: this.changes || 0 });
      });
    });
  }

  public exec(sql: string): Promise<void> {
    return new Promise((resolve, reject) => {
      this.raw.exec(sql, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  /**
   * Executes multiple statements atomically inside a SQLite transaction.
   */
  public async transaction<T>(fn: () => Promise<T>): Promise<T> {
    await this.run('BEGIN IMMEDIATE TRANSACTION');
    try {
      const result = await fn();
      await this.run('COMMIT');
      return result;
    } catch (err) {
      try {
        await this.run('ROLLBACK');
      } catch {
        // Ignore rollback secondary error
      }
      throw err;
    }
  }

  /**
   * Creates an automatic timestamped backup of data/tgvpanel.db before running migrations.
   */
  public async createBackup(label = 'auto'): Promise<{ backupPath: string; sizeBytes: number }> {
    const dir = path.join(path.dirname(this.dbPath), 'backups');
    fs.mkdirSync(dir, { recursive: true });
    const ts = new Date().toISOString().replace(/[:.]/g, '-');
    const safeLabel = label.replace(/[^a-zA-Z0-9_-]/g, '_');
    const backupPath = path.join(dir, `tgvpanel_${safeLabel}_${ts}.db`);

    // Checkpoint WAL first so the copy is self-contained, then use VACUUM INTO if supported
    try {
      await this.run('PRAGMA wal_checkpoint(PASSIVE)');
      const escaped = backupPath.replace(/'/g, "''");
      await this.run(`VACUUM INTO '${escaped}'`);
    } catch {
      fs.copyFileSync(this.dbPath, backupPath);
    }

    const stat = fs.statSync(backupPath);
    return { backupPath, sizeBytes: stat.size };
  }

  public async logActivity(params: {
    userId?: number | null;
    action: string;
    resourceType?: string | null;
    resourceId?: string | number | null;
    details?: Record<string, any> | string | null;
    ipAddress?: string | null;
    userAgent?: string | null;
  }): Promise<void> {
    try {
      const detailsStr =
        params.details === null || params.details === undefined
          ? null
          : typeof params.details === 'string'
          ? params.details
          : JSON.stringify(params.details);
      await this.run(
        `INSERT INTO activity_logs (user_id, action, resource_type, resource_id, details, ip_address, user_agent, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
        [
          params.userId ?? null,
          params.action,
          params.resourceType ?? null,
          params.resourceId !== undefined && params.resourceId !== null
            ? String(params.resourceId)
            : null,
          detailsStr,
          params.ipAddress ?? null,
          params.userAgent ?? null,
        ]
      );
    } catch {
      // Never crash caller if audit table is mid-initialization
    }
  }

  public close(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.raw.close((err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }
}

let singletonDb: UnifiedDatabase | null = null;

export function registerUnifiedDatabase(rawDb: sqlite3.Database, dbPath: string): UnifiedDatabase {
  singletonDb = new UnifiedDatabase(rawDb, dbPath);
  return singletonDb;
}

export function getUnifiedDatabase(): UnifiedDatabase {
  if (!singletonDb) {
    throw new Error('UnifiedDatabase has not been initialized yet');
  }
  return singletonDb;
}
