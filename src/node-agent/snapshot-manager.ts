import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import {
  findActiveMountSource,
  isBinaryAvailable,
  isRunningAsRoot,
  privilegedFs,
  runAllowlistedCommand,
} from './command-runner';
import { SafeValidators } from '../security/middleware';

export interface SnapshotInfo {
  name: string;
  comment: string;
  timestamp: string;
  sizeBytes: number;
}

export interface BackupArtifact {
  backupName: string;
  filePath: string;
  sizeBytes: number;
  checksumSha256: string;
  createdAt: string;
}

const DEFAULT_BACKUP_DIR =
  process.env.TGVPANEL_BACKUP_DIR ||
  process.env.HKVM_BACKUP_DIR ||
  path.resolve(process.cwd(), 'data', 'instance-backups');
const DEFAULT_LXC_BASE =
  process.env.TGVPANEL_LXC_PATH ||
  process.env.TGVPANEL_LXC_DIR ||
  process.env.HKVM_LXC_PATH ||
  '/var/lib/lxc';

export class LxcSnapshotAndBackupManager {
  private backupDir: string;
  private lxcBaseDir: string;

  constructor(backupDir = DEFAULT_BACKUP_DIR, lxcBaseDir = DEFAULT_LXC_BASE) {
    this.backupDir = path.resolve(backupDir);
    this.lxcBaseDir = path.resolve(lxcBaseDir);
    fs.mkdirSync(this.backupDir, { recursive: true });
  }

  public getBackupDir(): string {
    return this.backupDir;
  }

  public resolveConfinedBackupPath(filePath: string): string {
    const resolved = path.resolve(filePath);
    if (resolved !== this.backupDir && !resolved.startsWith(this.backupDir + path.sep)) {
      throw new Error('Backup path is outside the configured node backup directory.');
    }
    return resolved;
  }

  private needsRootForStore(): boolean {
    if (isRunningAsRoot()) return false;
    if (this.lxcBaseDir === '/var/lib/lxc' || this.lxcBaseDir.startsWith('/var/lib/lxc/')) {
      return true;
    }
    try {
      if (fs.existsSync(this.lxcBaseDir)) {
        fs.accessSync(this.lxcBaseDir, fs.constants.R_OK | fs.constants.W_OK | fs.constants.X_OK);
        return false;
      }
      return false;
    } catch {
      return true;
    }
  }

  private lxcPathArgs(): string[] {
    return ['-P', this.lxcBaseDir];
  }

  public async listSnapshots(containerName: string): Promise<SnapshotInfo[]> {
    const safeName = SafeValidators.containerName(containerName);
    if (!isBinaryAvailable('lxc-snapshot')) return [];

    const res = await runAllowlistedCommand(
      'lxc-snapshot',
      [...this.lxcPathArgs(), '-n', safeName, '-L', '-C'],
      {
        timeoutMs: 15_000,
        asRoot: this.needsRootForStore() || undefined,
      }
    );
    if (res.exitCode !== 0) return [];

    const snaps: SnapshotInfo[] = [];
    for (const line of res.stdout.trim().split('\n').filter(Boolean)) {
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 3) {
        const snapName = parts[0];
        const ts = `${parts[2]} ${parts[3] || ''}`.trim();
        snaps.push({
          name: snapName,
          comment: parts.slice(4).join(' '),
          timestamp: ts,
          sizeBytes: 0,
        });
      }
    }
    return snaps;
  }

  public async createSnapshot(containerName: string, comment = ''): Promise<SnapshotInfo> {
    if (!isBinaryAvailable('lxc-snapshot')) {
      throw new Error('lxc-snapshot binary is not installed on this node.');
    }
    const safeName = SafeValidators.containerName(containerName);

    let commentFile: string | null = null;
    try {
      const args = [...this.lxcPathArgs(), '-n', safeName];
      if (comment) {
        commentFile = path.join(this.backupDir, `.snap_comment_${Date.now()}.txt`);
        fs.writeFileSync(commentFile, comment.slice(0, 500), { mode: 0o644 });
        args.push('-c', commentFile);
      }

      const res = await runAllowlistedCommand('lxc-snapshot', args, {
        timeoutMs: 120_000,
        asRoot: this.needsRootForStore() || undefined,
      });
      if (res.exitCode !== 0) {
        throw new Error(`lxc-snapshot create failed: ${res.stderr || res.stdout}`);
      }

      const list = await this.listSnapshots(safeName);
      const latest = list[list.length - 1] || {
        name: `snap0`,
        comment,
        timestamp: new Date().toISOString(),
        sizeBytes: 0,
      };
      return latest;
    } finally {
      if (commentFile && fs.existsSync(commentFile)) {
        fs.unlinkSync(commentFile);
      }
    }
  }

  public async restoreSnapshot(containerName: string, snapshotName: string): Promise<void> {
    if (!isBinaryAvailable('lxc-snapshot')) {
      throw new Error('lxc-snapshot binary is not installed on this node.');
    }
    const safeName = SafeValidators.containerName(containerName);
    const safeSnap = SafeValidators.snapshotName(snapshotName);
    const res = await runAllowlistedCommand(
      'lxc-snapshot',
      [...this.lxcPathArgs(), '-n', safeName, '-r', safeSnap],
      {
        timeoutMs: 180_000,
        asRoot: this.needsRootForStore() || undefined,
      }
    );
    if (res.exitCode !== 0) {
      throw new Error(`lxc-snapshot restore failed: ${res.stderr || res.stdout}`);
    }
  }

  public async deleteSnapshot(containerName: string, snapshotName: string): Promise<void> {
    if (!isBinaryAvailable('lxc-snapshot')) {
      throw new Error('lxc-snapshot binary is not installed on this node.');
    }
    const safeName = SafeValidators.containerName(containerName);
    const safeSnap = SafeValidators.snapshotName(snapshotName);
    const res = await runAllowlistedCommand(
      'lxc-snapshot',
      [...this.lxcPathArgs(), '-n', safeName, '-d', safeSnap],
      {
        timeoutMs: 60_000,
        asRoot: this.needsRootForStore() || undefined,
      }
    );
    if (res.exitCode !== 0) {
      throw new Error(`lxc-snapshot delete failed: ${res.stderr || res.stdout}`);
    }
  }

  public async createTarBackup(
    containerName: string,
    backupLabel?: string
  ): Promise<BackupArtifact> {
    const safeName = SafeValidators.containerName(containerName);
    const containerDir = path.join(this.lxcBaseDir, safeName);
    if (!privilegedFs.existsSync(containerDir)) {
      throw new Error(`Container directory not found: ${containerDir}`);
    }

    const safeLabel = backupLabel
      ? SafeValidators.snapshotName(backupLabel)
      : `bkp_${Date.now()}`;
    const fileName = `${safeName}_${safeLabel}.tar.gz`;
    const archivePath = path.join(this.backupDir, fileName);

    const tarRes = await runAllowlistedCommand(
      'tar',
      ['--numeric-owner', '-czpf', archivePath, '-C', this.lxcBaseDir, safeName],
      {
        timeoutMs: 900_000,
        asRoot: true,
      }
    );
    if (tarRes.exitCode !== 0) {
      throw new Error(`tar backup failed: ${tarRes.stderr || tarRes.stdout}`);
    }

    privilegedFs.chownToCurrentUserSync(archivePath);

    const checksumSha256 = await this.computeFileSha256(archivePath);
    const st = fs.statSync(archivePath);

    return {
      backupName: safeLabel,
      filePath: archivePath,
      sizeBytes: st.size,
      checksumSha256,
      createdAt: new Date().toISOString(),
    };
  }

  public async restoreTarBackup(
    archivePath: string,
    expectedChecksumSha256?: string,
    cleanContainerName?: string
  ): Promise<void> {
    const resolved = path.resolve(archivePath);
    if (!fs.existsSync(resolved)) {
      throw new Error(`Backup archive not found: ${resolved}`);
    }

    if (expectedChecksumSha256) {
      const actual = await this.computeFileSha256(resolved);
      if (actual.toLowerCase() !== expectedChecksumSha256.toLowerCase()) {
        throw new Error(
          `Backup integrity check failed: expected SHA-256 ${expectedChecksumSha256}, got ${actual}`
        );
      }
    }

    privilegedFs.mkdirpSync(this.lxcBaseDir, 0o755);
    if (cleanContainerName) {
      const safeName = SafeValidators.containerName(cleanContainerName);
      const existingRootfs = path.join(this.lxcBaseDir, safeName, 'rootfs');
      if (privilegedFs.existsSync(existingRootfs)) {
        if (findActiveMountSource(existingRootfs)) {
          // Preserve active loop mountpoint directory; clear only its inner entries
          for (const child of privilegedFs.readdirNamesSync(existingRootfs)) {
            if (child === 'lost+found') continue;
            privilegedFs.rmRecursiveSync(path.join(existingRootfs, child));
          }
        } else {
          privilegedFs.rmRecursiveSync(existingRootfs);
        }
      }
    }

    const untarRes = await runAllowlistedCommand(
      'tar',
      ['--numeric-owner', '-xzpf', resolved, '-C', this.lxcBaseDir],
      {
        timeoutMs: 900_000,
        asRoot: true,
      }
    );
    if (untarRes.exitCode !== 0) {
      throw new Error(`tar restore failed: ${untarRes.stderr || untarRes.stdout}`);
    }
  }

  public computeFileSha256(filePath: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const hash = crypto.createHash('sha256');
      const stream = fs.createReadStream(filePath);
      stream.on('data', (chunk) => hash.update(chunk));
      stream.on('error', reject);
      stream.on('end', () => resolve(hash.digest('hex')));
    });
  }
}
