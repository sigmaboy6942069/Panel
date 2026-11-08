"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.KVMAdapter = void 0;
const crypto_1 = __importDefault(require("crypto"));
const fs_1 = __importDefault(require("fs"));
const os_1 = __importDefault(require("os"));
const path_1 = __importDefault(require("path"));
const command_runner_1 = require("../../node-agent/command-runner");
const middleware_1 = require("../../security/middleware");
/**
 * Real QEMU/KVM hypervisor adapter wrapping HKVM's `vms` (`vm_id`, `vm_name`, `owner_id`, `disk_file`)
 * records, Linux `/proc/<pid>` telemetry, and real `qemu-img` snapshot/backup operations.
 */
class KVMAdapter {
    engine = 'kvm';
    db;
    hooks;
    prevPidTicks = new Map();
    constructor(db, hooks = {}) {
        this.db = db;
        this.hooks = hooks;
    }
    setLegacyHooks(hooks) {
        this.hooks = { ...this.hooks, ...hooks };
    }
    getCapabilityProfile() {
        return {
            engine: 'kvm',
            supportsFreeze: false,
            supportsSuspend: true,
            supportsSnapshots: true,
            supportsBackups: true,
            supportsOfflineMigration: false,
            supportsIsoMount: true,
            supportsBootOrder: true,
            supportsSmbios: true,
            supportsCloudInit: true,
            supportsSerialConsole: true,
            supportsPtyConsole: false,
            supportsSshBridge: true,
            supportsRootfsFileBrowser: false,
            supportsContainerProcessList: false,
        };
    }
    resolveVmDiskPath(row) {
        const candidate = row.disk_file || row.img_file || null;
        if (!candidate)
            return null;
        if (path_1.default.isAbsolute(candidate))
            return candidate;
        return path_1.default.join(os_1.default.homedir(), 'vms', candidate);
    }
    parseDiskGb(diskSizeVal) {
        return parseFloat(String(diskSizeVal || '20').replace(/[^0-9.]/g, '')) || 20;
    }
    mapRowToUnified(row) {
        let shared = [];
        try {
            const parsed = JSON.parse(row.shared_with || '[]');
            if (Array.isArray(parsed))
                shared = parsed.map(Number).filter(Boolean);
        }
        catch {
            shared = [];
        }
        const refId = Number(row.vm_id ?? row.id);
        const vmName = row.vm_name || row.name || `vm-${refId}`;
        return {
            uid: `kvm:${refId}`,
            engine: 'kvm',
            refId,
            name: vmName,
            hostname: row.hostname || vmName,
            ownerId: Number(row.owner_id || 1),
            ownerUsername: row.owner_username || undefined,
            nodeId: Number(row.node_id || 1),
            nodeName: row.resolved_node_name || row.node_name || 'localhost',
            status: row.suspended ? 'suspended' : row.status || 'stopped',
            suspended: Boolean(row.suspended),
            suspendedReason: row.suspended_reason || null,
            osLabel: row.os_type || 'KVM Guest',
            cpuCores: Number(row.cpus || row.cpu_cores || 1),
            ramMb: Number(row.memory || 1024),
            swapMb: 0,
            diskGb: this.parseDiskGb(row.disk_size),
            primaryIp: row.ipv4_address || '127.0.0.1',
            sshPort: row.ssh_port || null,
            sharedWith: shared,
            expiresAt: row.expires_at || null,
            createdAt: row.created_at,
            capabilities: this.getCapabilityProfile(),
        };
    }
    async listInstances(filter) {
        const clauses = [];
        const params = [];
        if (filter?.ownerId !== undefined) {
            clauses.push(`(v.owner_id = ? OR COALESCE(v.shared_with, '[]') LIKE ?)`);
            params.push(filter.ownerId, `%${filter.ownerId}%`);
        }
        if (filter?.nodeId !== undefined) {
            clauses.push(`COALESCE(v.node_id, 1) = ?`);
            params.push(filter.nodeId);
        }
        const whereSql = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
        const rows = await this.db.all(`SELECT v.*, u.username AS owner_username, n.name AS resolved_node_name
       FROM vms v
       LEFT JOIN users u ON u.id = v.owner_id
       LEFT JOIN nodes n ON n.id = COALESCE(v.node_id, 1)
       ${whereSql}
       ORDER BY v.vm_id DESC`, params);
        const mapped = rows.map((r) => this.mapRowToUnified(r));
        if (filter?.ownerId !== undefined) {
            return mapped.filter((m) => m.ownerId === filter.ownerId || m.sharedWith.includes(filter.ownerId));
        }
        return mapped;
    }
    async getInstance(refId) {
        const row = await this.db.get(`SELECT v.*, u.username AS owner_username, n.name AS resolved_node_name
       FROM vms v
       LEFT JOIN users u ON u.id = v.owner_id
       LEFT JOIN nodes n ON n.id = COALESCE(v.node_id, 1)
       WHERE v.vm_id = ?`, [refId]);
        return row ? this.mapRowToUnified(row) : undefined;
    }
    async syncRegistryRow(vmId) {
        const vm = await this.db.get(`SELECT * FROM vms WHERE vm_id = ?`, [vmId]);
        if (!vm) {
            await this.db.run(`DELETE FROM instances WHERE engine = 'kvm' AND ref_id = ?`, [vmId]);
            return;
        }
        await this.db.run(`INSERT INTO instances
         (engine, ref_id, name, hostname, owner_id, node_id, status, suspended, os_label, cpu_cores, ram_mb, disk_gb, primary_ip, shared_with, updated_at)
       VALUES ('kvm', ?, ?, ?, ?, COALESCE(?, 1), ?, COALESCE(?, 0), ?, ?, ?, ?, ?, COALESCE(?, '[]'), datetime('now'))
       ON CONFLICT(engine, ref_id) DO UPDATE SET
         name = excluded.name,
         hostname = excluded.hostname,
         owner_id = excluded.owner_id,
         node_id = excluded.node_id,
         status = excluded.status,
         suspended = excluded.suspended,
         os_label = excluded.os_label,
         cpu_cores = excluded.cpu_cores,
         ram_mb = excluded.ram_mb,
         disk_gb = excluded.disk_gb,
         primary_ip = excluded.primary_ip,
         shared_with = excluded.shared_with,
         updated_at = datetime('now')`, [
            vm.vm_id,
            vm.vm_name,
            vm.hostname || vm.vm_name,
            vm.owner_id || 1,
            vm.node_id,
            vm.status || 'stopped',
            vm.suspended,
            vm.os_type || 'KVM Guest',
            vm.cpus || 1,
            vm.memory || 1024,
            this.parseDiskGb(vm.disk_size),
            vm.ipv4_address || null,
            vm.shared_with || '[]',
        ]);
    }
    async performLifecycleAction(refId, action, options) {
        const vm = await this.db.get(`SELECT * FROM vms WHERE vm_id = ?`, [refId]);
        if (!vm)
            throw new Error(`KVM VM #${refId} not found.`);
        if (action === 'freeze' || action === 'unfreeze') {
            throw new Error(`Action "${action}" is only supported for LXC containers, not KVM VMs.`);
        }
        if (action === 'start') {
            if (vm.suspended) {
                throw new Error('Cannot start a suspended VM. Unsuspend it first.');
            }
            if (!this.hooks.startVmById) {
                throw new Error('KVM start hook is not registered.');
            }
            await this.hooks.startVmById(refId);
        }
        else if (action === 'stop') {
            if (this.hooks.stopVmById) {
                await this.hooks.stopVmById(refId, options?.force);
            }
            else {
                if (vm.pid) {
                    try {
                        process.kill(Number(vm.pid), options?.force ? 'SIGKILL' : 'SIGTERM');
                    }
                    catch {
                        // already exited
                    }
                }
                await this.db.run(`UPDATE vms SET status = 'stopped', pid = NULL WHERE vm_id = ?`, [refId]);
            }
        }
        else if (action === 'restart') {
            if (this.hooks.restartVmById) {
                await this.hooks.restartVmById(refId);
            }
            else {
                if (this.hooks.stopVmById)
                    await this.hooks.stopVmById(refId, false);
                if (this.hooks.startVmById)
                    await this.hooks.startVmById(refId);
            }
        }
        else if (action === 'suspend') {
            if (vm.status === 'running' && this.hooks.stopVmById) {
                await this.hooks.stopVmById(refId, false);
            }
            await this.db.run(`UPDATE vms SET suspended = 1, suspended_reason = ?, status = 'stopped', pid = NULL WHERE vm_id = ?`, [options?.reason || 'Suspended by administrator', refId]);
        }
        else if (action === 'unsuspend') {
            await this.db.run(`UPDATE vms SET suspended = 0, suspended_reason = NULL WHERE vm_id = ?`, [refId]);
        }
        else if (action === 'delete') {
            if (this.hooks.deleteVmById) {
                await this.hooks.deleteVmById(refId);
            }
            else {
                await this.db.run(`DELETE FROM vm_logs WHERE vm_id = ?`, [refId]).catch(() => undefined);
                await this.db
                    .run(`DELETE FROM vm_snapshots WHERE vm_id = ?`, [refId])
                    .catch(() => undefined);
                await this.db.run(`DELETE FROM vms WHERE vm_id = ?`, [refId]);
            }
            await this.db.run(`DELETE FROM instances WHERE engine = 'kvm' AND ref_id = ?`, [refId]);
            return this.mapRowToUnified({ ...vm, status: 'deleted' });
        }
        await this.syncRegistryRow(refId);
        return (await this.getInstance(refId));
    }
    async getTelemetry(refId) {
        const vm = await this.db.get(`SELECT * FROM vms WHERE vm_id = ?`, [refId]);
        if (!vm)
            throw new Error(`KVM VM #${refId} not found.`);
        const pid = vm.pid ? Number(vm.pid) : null;
        let isAlive = false;
        let cpuPercent = 0;
        let ramUsedMb = 0;
        if (pid && pid > 0 && fs_1.default.existsSync(`/proc/${pid}/stat`)) {
            isAlive = true;
            try {
                const statContent = fs_1.default.readFileSync(`/proc/${pid}/stat`, 'utf8');
                const afterComm = statContent.slice(statContent.lastIndexOf(')') + 2).trim().split(/\s+/);
                const utime = parseInt(afterComm[11] || '0', 10) || 0;
                const stime = parseInt(afterComm[12] || '0', 10) || 0;
                const procJiffies = utime + stime;
                const nowMs = Date.now();
                const clkTck = 100;
                const prev = this.prevPidTicks.get(pid);
                if (prev && nowMs > prev.tsMs) {
                    const deltaSec = (nowMs - prev.tsMs) / 1000;
                    const cpuSec = (procJiffies - prev.procJiffies) / clkTck;
                    const vcpus = Math.max(1, Number(vm.cpus || 1));
                    cpuPercent = Number(Math.min(100, Math.max(0, ((cpuSec / deltaSec) / vcpus) * 100)).toFixed(2));
                }
                this.prevPidTicks.set(pid, { procJiffies, tsMs: nowMs });
                const statusContent = fs_1.default.readFileSync(`/proc/${pid}/status`, 'utf8');
                const rssMatch = statusContent.match(/^VmRSS:\s+(\d+)\s+kB/m);
                if (rssMatch) {
                    ramUsedMb = Math.round(parseInt(rssMatch[1], 10) / 1024);
                }
            }
            catch {
                isAlive = false;
            }
        }
        const diskPath = this.resolveVmDiskPath(vm);
        let diskUsedGb = 0;
        if (diskPath && fs_1.default.existsSync(diskPath)) {
            try {
                diskUsedGb = Number((fs_1.default.statSync(diskPath).size / 1024 ** 3).toFixed(2));
            }
            catch {
                diskUsedGb = 0;
            }
        }
        const ramTotalMb = Math.max(1, Number(vm.memory || 1024));
        const status = isAlive ? 'running' : vm.status === 'running' ? 'stopped' : vm.status || 'stopped';
        return {
            engine: 'kvm',
            refId,
            status,
            pid: isAlive ? pid : null,
            cpuPercent,
            ramUsedMb,
            ramTotalMb,
            ramPercent: Number(Math.min(100, (ramUsedMb / ramTotalMb) * 100).toFixed(2)),
            diskUsedGb,
            diskTotalGb: this.parseDiskGb(vm.disk_size),
            netRxBytes: 0,
            netTxBytes: 0,
            measuredAt: new Date().toISOString(),
        };
    }
    async createQcow2Snapshot(vmId, snapshotName, description = '') {
        const safeSnap = middleware_1.SafeValidators.snapshotName(snapshotName);
        const vm = await this.db.get(`SELECT * FROM vms WHERE vm_id = ?`, [vmId]);
        if (!vm)
            throw new Error(`KVM VM #${vmId} not found.`);
        if ((vm.disk_format || 'qcow2').toLowerCase() !== 'qcow2') {
            throw new Error('Internal QEMU snapshots require QCOW2 disk format (current disk is RAW).');
        }
        if (!(0, command_runner_1.isBinaryAvailable)('qemu-img')) {
            throw new Error('qemu-img binary is not installed on this host.');
        }
        const diskPath = this.resolveVmDiskPath(vm);
        if (!diskPath || !fs_1.default.existsSync(diskPath)) {
            throw new Error(`VM disk image does not exist on disk: ${diskPath}`);
        }
        const res = await (0, command_runner_1.runAllowlistedCommand)('qemu-img', ['snapshot', '-c', safeSnap, diskPath], {
            timeoutMs: 120_000,
        });
        if (res.exitCode !== 0) {
            throw new Error(`qemu-img snapshot failed: ${res.stderr || res.stdout}`);
        }
        const sizeGb = Number((fs_1.default.statSync(diskPath).size / 1024 ** 3).toFixed(2));
        const ins = await this.db.run(`INSERT INTO vm_snapshots (vm_id, snapshot_name, tag_name, file_path, size_gb, description, status)
       VALUES (?, ?, ?, ?, ?, ?, 'completed')`, [vmId, safeSnap, safeSnap, diskPath, sizeGb, description]);
        return { id: ins.lastID, name: safeSnap };
    }
    async restoreQcow2Snapshot(vmId, snapshotId) {
        const vm = await this.db.get(`SELECT * FROM vms WHERE vm_id = ?`, [vmId]);
        const snap = await this.db.get(`SELECT * FROM vm_snapshots WHERE snapshot_id = ? AND vm_id = ?`, [snapshotId, vmId]);
        if (!vm || !snap)
            throw new Error('VM or snapshot not found.');
        if (vm.status === 'running') {
            throw new Error('Stop the KVM VM before reverting to a disk snapshot.');
        }
        if (!(0, command_runner_1.isBinaryAvailable)('qemu-img')) {
            throw new Error('qemu-img binary is not installed on this host.');
        }
        const diskPath = this.resolveVmDiskPath(vm);
        if (!diskPath || !fs_1.default.existsSync(diskPath)) {
            throw new Error(`VM disk image not found: ${diskPath}`);
        }
        const res = await (0, command_runner_1.runAllowlistedCommand)('qemu-img', ['snapshot', '-a', snap.snapshot_name, diskPath], { timeoutMs: 120_000 });
        if (res.exitCode !== 0) {
            throw new Error(`qemu-img snapshot revert failed: ${res.stderr || res.stdout}`);
        }
    }
    async deleteQcow2Snapshot(vmId, snapshotId) {
        const vm = await this.db.get(`SELECT * FROM vms WHERE vm_id = ?`, [vmId]);
        const snap = await this.db.get(`SELECT * FROM vm_snapshots WHERE snapshot_id = ? AND vm_id = ?`, [snapshotId, vmId]);
        if (!vm || !snap)
            throw new Error('VM or snapshot not found.');
        const diskPath = this.resolveVmDiskPath(vm);
        if ((0, command_runner_1.isBinaryAvailable)('qemu-img') && diskPath && fs_1.default.existsSync(diskPath)) {
            await (0, command_runner_1.runAllowlistedCommand)('qemu-img', ['snapshot', '-d', snap.snapshot_name, diskPath], {
                timeoutMs: 60_000,
            });
        }
        await this.db.run(`DELETE FROM vm_snapshots WHERE snapshot_id = ?`, [snapshotId]);
    }
    async createDiskBackup(vmId, backupDir = path_1.default.resolve(process.cwd(), 'data', 'instance-backups')) {
        const vm = await this.db.get(`SELECT * FROM vms WHERE vm_id = ?`, [vmId]);
        if (!vm)
            throw new Error(`KVM VM #${vmId} not found.`);
        const diskPath = this.resolveVmDiskPath(vm);
        if (!diskPath || !fs_1.default.existsSync(diskPath)) {
            throw new Error(`VM disk image not found at ${diskPath}`);
        }
        fs_1.default.mkdirSync(backupDir, { recursive: true });
        const backupName = `kvm_${vm.vm_id}_${Date.now()}`;
        const outFile = path_1.default.join(backupDir, `${backupName}.tar.gz`);
        const diskDir = path_1.default.dirname(diskPath);
        const diskBase = path_1.default.basename(diskPath);
        const tarRes = await (0, command_runner_1.runAllowlistedCommand)('tar', ['-czpf', outFile, '-C', diskDir, diskBase], {
            timeoutMs: 900_000,
        });
        if (tarRes.exitCode !== 0) {
            throw new Error(`KVM disk backup failed: ${tarRes.stderr || tarRes.stdout}`);
        }
        const hash = crypto_1.default.createHash('sha256');
        await new Promise((resolve, reject) => {
            const s = fs_1.default.createReadStream(outFile);
            s.on('data', (c) => hash.update(c));
            s.on('error', reject);
            s.on('end', () => resolve());
        });
        const checksumSha256 = hash.digest('hex');
        const sizeBytes = fs_1.default.statSync(outFile).size;
        const ins = await this.db.run(`INSERT INTO container_backups
         (instance_type, instance_ref_id, node_id, backup_name, file_path, size_bytes, sha256, checksum_sha256, verified, status)
       VALUES ('kvm', ?, COALESCE(?, 1), ?, ?, ?, ?, ?, 1, 'completed')`, [vm.vm_id, vm.node_id, backupName, outFile, sizeBytes, checksumSha256, checksumSha256]);
        return { backupId: ins.lastID, filePath: outFile, sizeBytes, checksumSha256 };
    }
}
exports.KVMAdapter = KVMAdapter;
