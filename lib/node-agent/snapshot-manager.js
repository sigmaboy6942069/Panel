"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.LxcSnapshotAndBackupManager = void 0;
const crypto_1 = __importDefault(require("crypto"));
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const command_runner_1 = require("./command-runner");
const middleware_1 = require("../security/middleware");
const DEFAULT_BACKUP_DIR = process.env.TGVPANEL_BACKUP_DIR ||
    process.env.HKVM_BACKUP_DIR ||
    path_1.default.resolve(process.cwd(), 'data', 'instance-backups');
const DEFAULT_LXC_BASE = process.env.TGVPANEL_LXC_PATH ||
    process.env.TGVPANEL_LXC_DIR ||
    process.env.HKVM_LXC_PATH ||
    '/var/lib/lxc';
class LxcSnapshotAndBackupManager {
    backupDir;
    lxcBaseDir;
    constructor(backupDir = DEFAULT_BACKUP_DIR, lxcBaseDir = DEFAULT_LXC_BASE) {
        this.backupDir = path_1.default.resolve(backupDir);
        this.lxcBaseDir = path_1.default.resolve(lxcBaseDir);
        fs_1.default.mkdirSync(this.backupDir, { recursive: true });
    }
    getBackupDir() {
        return this.backupDir;
    }
    resolveConfinedBackupPath(filePath) {
        const resolved = path_1.default.resolve(filePath);
        if (resolved !== this.backupDir && !resolved.startsWith(this.backupDir + path_1.default.sep)) {
            throw new Error('Backup path is outside the configured node backup directory.');
        }
        return resolved;
    }
    needsRootForStore() {
        if ((0, command_runner_1.isRunningAsRoot)())
            return false;
        if (this.lxcBaseDir === '/var/lib/lxc' || this.lxcBaseDir.startsWith('/var/lib/lxc/')) {
            return true;
        }
        try {
            if (fs_1.default.existsSync(this.lxcBaseDir)) {
                fs_1.default.accessSync(this.lxcBaseDir, fs_1.default.constants.R_OK | fs_1.default.constants.W_OK | fs_1.default.constants.X_OK);
                return false;
            }
            return false;
        }
        catch {
            return true;
        }
    }
    lxcPathArgs() {
        return ['-P', this.lxcBaseDir];
    }
    async listSnapshots(containerName) {
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        if (!(0, command_runner_1.isBinaryAvailable)('lxc-snapshot'))
            return [];
        const res = await (0, command_runner_1.runAllowlistedCommand)('lxc-snapshot', [...this.lxcPathArgs(), '-n', safeName, '-L', '-C'], {
            timeoutMs: 15_000,
            asRoot: this.needsRootForStore() || undefined,
        });
        if (res.exitCode !== 0)
            return [];
        const snaps = [];
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
    async createSnapshot(containerName, comment = '') {
        if (!(0, command_runner_1.isBinaryAvailable)('lxc-snapshot')) {
            throw new Error('lxc-snapshot binary is not installed on this node.');
        }
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        let commentFile = null;
        try {
            const args = [...this.lxcPathArgs(), '-n', safeName];
            if (comment) {
                commentFile = path_1.default.join(this.backupDir, `.snap_comment_${Date.now()}.txt`);
                fs_1.default.writeFileSync(commentFile, comment.slice(0, 500), { mode: 0o644 });
                args.push('-c', commentFile);
            }
            const res = await (0, command_runner_1.runAllowlistedCommand)('lxc-snapshot', args, {
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
        }
        finally {
            if (commentFile && fs_1.default.existsSync(commentFile)) {
                fs_1.default.unlinkSync(commentFile);
            }
        }
    }
    async restoreSnapshot(containerName, snapshotName) {
        if (!(0, command_runner_1.isBinaryAvailable)('lxc-snapshot')) {
            throw new Error('lxc-snapshot binary is not installed on this node.');
        }
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        const safeSnap = middleware_1.SafeValidators.snapshotName(snapshotName);
        const res = await (0, command_runner_1.runAllowlistedCommand)('lxc-snapshot', [...this.lxcPathArgs(), '-n', safeName, '-r', safeSnap], {
            timeoutMs: 180_000,
            asRoot: this.needsRootForStore() || undefined,
        });
        if (res.exitCode !== 0) {
            throw new Error(`lxc-snapshot restore failed: ${res.stderr || res.stdout}`);
        }
    }
    async deleteSnapshot(containerName, snapshotName) {
        if (!(0, command_runner_1.isBinaryAvailable)('lxc-snapshot')) {
            throw new Error('lxc-snapshot binary is not installed on this node.');
        }
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        const safeSnap = middleware_1.SafeValidators.snapshotName(snapshotName);
        const res = await (0, command_runner_1.runAllowlistedCommand)('lxc-snapshot', [...this.lxcPathArgs(), '-n', safeName, '-d', safeSnap], {
            timeoutMs: 60_000,
            asRoot: this.needsRootForStore() || undefined,
        });
        if (res.exitCode !== 0) {
            throw new Error(`lxc-snapshot delete failed: ${res.stderr || res.stdout}`);
        }
    }
    async createTarBackup(containerName, backupLabel) {
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        const containerDir = path_1.default.join(this.lxcBaseDir, safeName);
        if (!command_runner_1.privilegedFs.existsSync(containerDir)) {
            throw new Error(`Container directory not found: ${containerDir}`);
        }
        const safeLabel = backupLabel
            ? middleware_1.SafeValidators.snapshotName(backupLabel)
            : `bkp_${Date.now()}`;
        const fileName = `${safeName}_${safeLabel}.tar.gz`;
        const archivePath = path_1.default.join(this.backupDir, fileName);
        const tarRes = await (0, command_runner_1.runAllowlistedCommand)('tar', ['--numeric-owner', '-czpf', archivePath, '-C', this.lxcBaseDir, safeName], {
            timeoutMs: 900_000,
            asRoot: true,
        });
        if (tarRes.exitCode !== 0) {
            throw new Error(`tar backup failed: ${tarRes.stderr || tarRes.stdout}`);
        }
        command_runner_1.privilegedFs.chownToCurrentUserSync(archivePath);
        const checksumSha256 = await this.computeFileSha256(archivePath);
        const st = fs_1.default.statSync(archivePath);
        return {
            backupName: safeLabel,
            filePath: archivePath,
            sizeBytes: st.size,
            checksumSha256,
            createdAt: new Date().toISOString(),
        };
    }
    async restoreTarBackup(archivePath, expectedChecksumSha256, cleanContainerName) {
        const resolved = path_1.default.resolve(archivePath);
        if (!fs_1.default.existsSync(resolved)) {
            throw new Error(`Backup archive not found: ${resolved}`);
        }
        if (expectedChecksumSha256) {
            const actual = await this.computeFileSha256(resolved);
            if (actual.toLowerCase() !== expectedChecksumSha256.toLowerCase()) {
                throw new Error(`Backup integrity check failed: expected SHA-256 ${expectedChecksumSha256}, got ${actual}`);
            }
        }
        command_runner_1.privilegedFs.mkdirpSync(this.lxcBaseDir, 0o755);
        if (cleanContainerName) {
            const safeName = middleware_1.SafeValidators.containerName(cleanContainerName);
            const existingRootfs = path_1.default.join(this.lxcBaseDir, safeName, 'rootfs');
            if (command_runner_1.privilegedFs.existsSync(existingRootfs)) {
                if ((0, command_runner_1.findActiveMountSource)(existingRootfs)) {
                    // Preserve active loop mountpoint directory; clear only its inner entries
                    for (const child of command_runner_1.privilegedFs.readdirNamesSync(existingRootfs)) {
                        if (child === 'lost+found')
                            continue;
                        command_runner_1.privilegedFs.rmRecursiveSync(path_1.default.join(existingRootfs, child));
                    }
                }
                else {
                    command_runner_1.privilegedFs.rmRecursiveSync(existingRootfs);
                }
            }
        }
        const untarRes = await (0, command_runner_1.runAllowlistedCommand)('tar', ['--numeric-owner', '-xzpf', resolved, '-C', this.lxcBaseDir], {
            timeoutMs: 900_000,
            asRoot: true,
        });
        if (untarRes.exitCode !== 0) {
            throw new Error(`tar restore failed: ${untarRes.stderr || untarRes.stdout}`);
        }
    }
    computeFileSha256(filePath) {
        return new Promise((resolve, reject) => {
            const hash = crypto_1.default.createHash('sha256');
            const stream = fs_1.default.createReadStream(filePath);
            stream.on('data', (chunk) => hash.update(chunk));
            stream.on('error', reject);
            stream.on('end', () => resolve(hash.digest('hex')));
        });
    }
}
exports.LxcSnapshotAndBackupManager = LxcSnapshotAndBackupManager;
