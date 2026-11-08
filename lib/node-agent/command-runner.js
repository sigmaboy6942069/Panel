"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.execFile = exports.privilegedFs = void 0;
exports.isAllowlistedBinary = isAllowlistedBinary;
exports.isRunningAsRoot = isRunningAsRoot;
exports.currentUsername = currentUsername;
exports.currentHomedir = currentHomedir;
exports.resolveSudoBinary = resolveSudoBinary;
exports.canPasswordlessSudo = canPasswordlessSudo;
exports.buildSafeSpawnEnv = buildSafeSpawnEnv;
exports.resolveBinaryPath = resolveBinaryPath;
exports.isBinaryAvailable = isBinaryAvailable;
exports.runAllowlistedCommand = runAllowlistedCommand;
exports.detectHostCapabilities = detectHostCapabilities;
exports.findActiveMountSource = findActiveMountSource;
exports.ensureLxcfsDaemonMounted = ensureLxcfsDaemonMounted;
const child_process_1 = require("child_process");
Object.defineProperty(exports, "execFile", { enumerable: true, get: function () { return child_process_1.execFile; } });
const fs_1 = __importDefault(require("fs"));
const os_1 = __importDefault(require("os"));
const path_1 = __importDefault(require("path"));
/**
 * Explicit allowlist of system binaries the HKVM Node Agent and Virtualization Adapters may invoke.
 * Commands are ALWAYS executed via `spawn` / `execFile` with argument arrays (`shell: false`).
 * Note: `sudo`, `su`, `sh`, `bash`, etc. are intentionally excluded from this allowlist.
 */
const ALLOWED_BINARIES = new Set([
    // LXC native tools
    'lxc-create',
    'lxc-start',
    'lxc-stop',
    'lxc-destroy',
    'lxc-info',
    'lxc-ls',
    'lxc-freeze',
    'lxc-unfreeze',
    'lxc-attach',
    'lxc-snapshot',
    'lxc-cgroup',
    'lxc-checkconfig',
    'lxc-config',
    'lxc-autostart',
    // QEMU / KVM tools
    'qemu-system-x86_64',
    'qemu-system-aarch64',
    'qemu-img',
    'cloud-localds',
    'genisoimage',
    'mkisofs',
    // Storage & archive tools
    'df',
    'du',
    'tar',
    'gzip',
    'sha256sum',
    'lvcreate',
    'lvremove',
    'lvextend',
    'lvs',
    'vgs',
    'zfs',
    'zpool',
    'btrfs',
    'truncate',
    'mkfs.ext4',
    'e2fsck',
    'resize2fs',
    'losetup',
    'mount',
    'umount',
    'lxcfs',
    // Linux networking & firewall tools
    'ip',
    'bridge',
    'iptables',
    'iptables-legacy',
    'iptables-save',
    'iptables-restore',
    'ip6tables',
    'ip6tables-legacy',
    'nft',
    'tc',
    'sysctl',
    'modprobe',
    // System inspection tools
    'uname',
    'uptime',
    'hostname',
    'ps',
    'free',
    'which',
    'openssl',
]);
/**
 * Binaries that manage system-wide hypervisor/container/network/volume state and require UID 0
 * when targeting host resources.
 */
function isAllowlistedBinary(binaryName) {
    return ALLOWED_BINARIES.has(binaryName);
}
const PRIVILEGED_SYSTEM_BINARIES = new Set([
    'lxc-create',
    'lxc-start',
    'lxc-stop',
    'lxc-destroy',
    'lxc-info',
    'lxc-ls',
    'lxc-freeze',
    'lxc-unfreeze',
    'lxc-attach',
    'lxc-snapshot',
    'lxc-cgroup',
    'lxc-autostart',
    'iptables',
    'iptables-legacy',
    'iptables-save',
    'iptables-restore',
    'ip6tables',
    'ip6tables-legacy',
    'nft',
    'tc',
    'modprobe',
    'lvcreate',
    'lvremove',
    'lvextend',
    'lvs',
    'vgs',
    'zfs',
    'zpool',
    'btrfs',
    'truncate',
    'mkfs.ext4',
    'e2fsck',
    'resize2fs',
    'losetup',
    'mount',
    'umount',
    'lxcfs',
]);
const SEARCH_DIRS = [
    '/usr/local/sbin',
    '/usr/local/bin',
    '/usr/sbin',
    '/usr/bin',
    '/sbin',
    '/bin',
];
function findSystemTool(name) {
    for (const dir of SEARCH_DIRS) {
        const candidate = path_1.default.join(dir, name);
        try {
            fs_1.default.accessSync(candidate, fs_1.default.constants.X_OK);
            return candidate;
        }
        catch {
            // continue
        }
    }
    return null;
}
function isRunningAsRoot() {
    return typeof process.getuid === 'function' && process.getuid() === 0;
}
function currentUsername() {
    try {
        return os_1.default.userInfo().username || process.env.USER || 'non-root';
    }
    catch {
        return process.env.USER || 'non-root';
    }
}
function currentHomedir() {
    try {
        const h = os_1.default.homedir();
        if (h && h !== '/')
            return h;
    }
    catch {
        // ignore
    }
    if (process.env.HOME && process.env.HOME !== '/') {
        return process.env.HOME;
    }
    return isRunningAsRoot() ? '/root' : '/tmp';
}
let cachedSudoState = {
    checked: false,
    available: false,
    sudoPath: null,
};
function resolveSudoBinary() {
    if (!cachedSudoState.checked) {
        canPasswordlessSudo();
    }
    return cachedSudoState.sudoPath;
}
/**
 * Checks once whether non-interactive passwordless `sudo -n` is available when HKVM
 * is started as a non-root user (e.g., `ubuntu` or `codespace` running `npm start`).
 */
function canPasswordlessSudo() {
    if (isRunningAsRoot())
        return false;
    if (cachedSudoState.checked)
        return cachedSudoState.available;
    const sudoPath = findSystemTool('sudo');
    if (!sudoPath) {
        cachedSudoState = { checked: true, available: false, sudoPath: null };
        return false;
    }
    try {
        (0, child_process_1.execFileSync)(sudoPath, ['-n', 'true'], {
            stdio: 'ignore',
            timeout: 3000,
        });
        cachedSudoState = { checked: true, available: true, sudoPath };
        return true;
    }
    catch {
        cachedSudoState = { checked: true, available: false, sudoPath };
        return false;
    }
}
function buildSafeSpawnEnv(effectiveRoot, extraEnv) {
    const baseHome = effectiveRoot ? '/root' : currentHomedir();
    const baseUser = effectiveRoot ? 'root' : currentUsername();
    const merged = {
        PATH: SEARCH_DIRS.join(':'),
        HOME: baseHome,
        USER: baseUser,
        LOGNAME: baseUser,
        LANG: 'C.UTF-8',
        LC_ALL: 'C.UTF-8',
    };
    if (extraEnv) {
        for (const [k, v] of Object.entries(extraEnv)) {
            if (typeof v === 'string' &&
                /^[A-Za-z_][A-Za-z0-9_]*$/.test(k) &&
                !k.includes('\0') &&
                !v.includes('\0') &&
                !v.includes('\n')) {
                merged[k] = v;
            }
        }
    }
    // Never allow HOME to collapse to empty or "/" (prevents liblxc mkdir("//.local/") bug)
    if (!merged.HOME || merged.HOME === '/') {
        merged.HOME = effectiveRoot ? '/root' : '/tmp';
    }
    return merged;
}
function resolveBinaryPath(binaryName) {
    const clean = path_1.default.basename(binaryName);
    if (!ALLOWED_BINARIES.has(clean)) {
        throw new Error(`Security policy violation: binary "${binaryName}" is not in the allowlist.`);
    }
    return findSystemTool(clean);
}
function isBinaryAvailable(binaryName) {
    try {
        return resolveBinaryPath(binaryName) !== null;
    }
    catch {
        return false;
    }
}
function isPureVersionProbe(args) {
    return args.length === 1 && (args[0] === '--version' || args[0] === '-v' || args[0] === '-V');
}
/**
 * Safely executes an allowlisted binary with `shell: false`, optional stdin pipe,
 * controlled `sudo -n` elevation for privileged host tools, valid `HOME` env,
 * hard timeout, and bounded stdout/stderr buffers.
 */
async function runAllowlistedCommand(binaryName, args = [], options = {}) {
    const cleanName = path_1.default.basename(binaryName);
    if (!ALLOWED_BINARIES.has(cleanName)) {
        throw new Error(`Security policy violation: binary "${binaryName}" is not in the allowlist.`);
    }
    for (const arg of args) {
        if (typeof arg !== 'string' || arg.includes('\0')) {
            throw new Error('Invalid command argument (null byte or non-string detected).');
        }
    }
    const resolved = resolveBinaryPath(cleanName);
    if (!resolved) {
        return {
            exitCode: 127,
            stdout: '',
            stderr: `Required host binary "${cleanName}" is not installed on this node.`,
            timedOut: false,
            durationMs: 0,
        };
    }
    const wantsRoot = options.asRoot !== undefined
        ? options.asRoot
        : PRIVILEGED_SYSTEM_BINARIES.has(cleanName) && !isPureVersionProbe(args);
    const alreadyRoot = isRunningAsRoot();
    const escalateWithSudo = !alreadyRoot && wantsRoot && canPasswordlessSudo();
    const effectiveRoot = alreadyRoot || escalateWithSudo;
    const safeEnv = buildSafeSpawnEnv(effectiveRoot, options.env);
    let spawnExecutable = resolved;
    let spawnArgs = args;
    if (escalateWithSudo && cachedSudoState.sudoPath) {
        const envBin = findSystemTool('env');
        spawnExecutable = cachedSudoState.sudoPath;
        if (envBin) {
            const envAssignments = Object.entries(safeEnv).map(([k, v]) => `${k}=${v}`);
            spawnArgs = ['-n', '--', envBin, ...envAssignments, resolved, ...args];
        }
        else {
            spawnArgs = ['-n', '--', resolved, ...args];
        }
    }
    const timeoutMs = options.timeoutMs ?? 60_000;
    const maxBytes = options.maxOutputBytes ?? 4 * 1024 * 1024;
    const startedAt = Date.now();
    return new Promise((resolve) => {
        const child = (0, child_process_1.spawn)(spawnExecutable, spawnArgs, {
            cwd: options.cwd || '/',
            env: safeEnv,
            shell: false,
            stdio: ['pipe', 'pipe', 'pipe'],
        });
        let stdoutBuf = '';
        let stderrBuf = '';
        let timedOut = false;
        let settled = false;
        const timer = setTimeout(() => {
            timedOut = true;
            try {
                child.kill('SIGKILL');
            }
            catch {
                // ignore
            }
        }, timeoutMs);
        child.stdout.on('data', (chunk) => {
            if (stdoutBuf.length < maxBytes) {
                stdoutBuf += chunk.toString('utf8').slice(0, maxBytes - stdoutBuf.length);
            }
        });
        child.stderr.on('data', (chunk) => {
            if (stderrBuf.length < maxBytes) {
                stderrBuf += chunk.toString('utf8').slice(0, maxBytes - stderrBuf.length);
            }
        });
        child.on('error', (err) => {
            if (settled)
                return;
            settled = true;
            clearTimeout(timer);
            resolve({
                exitCode: 126,
                stdout: stdoutBuf,
                stderr: err.message,
                timedOut,
                durationMs: Date.now() - startedAt,
            });
        });
        child.on('close', (code) => {
            if (settled)
                return;
            settled = true;
            clearTimeout(timer);
            const finalCode = code ?? (timedOut ? 124 : 1);
            let finalStderr = stderrBuf;
            if (finalCode !== 0 &&
                wantsRoot &&
                !effectiveRoot &&
                /permission denied|operation not permitted|must be root|not permitted/i.test(`${stderrBuf}\n${stdoutBuf}`)) {
                finalStderr = `${stderrBuf.trim()}\n[TGVPANEL Privilege Hint] Process is running as non-root user "${currentUsername()}" without passwordless sudo. Run TGVPANEL as root ("sudo npm start") or configure NOPASSWD sudo for LXC/network binaries.`.trim();
            }
            resolve({
                exitCode: finalCode,
                stdout: stdoutBuf,
                stderr: finalStderr,
                timedOut,
                durationMs: Date.now() - startedAt,
            });
        });
        if (options.stdinData !== undefined) {
            child.stdin.write(options.stdinData);
        }
        child.stdin.end();
    });
}
function isPermissionError(err) {
    const code = err?.code;
    return code === 'EACCES' || code === 'EPERM';
}
function assertSafeFsPath(targetPath) {
    if (!targetPath || typeof targetPath !== 'string' || targetPath.includes('\0')) {
        throw new Error('Invalid filesystem path.');
    }
    return path_1.default.resolve(targetPath);
}
function runSudoHelperSync(toolName, args, input) {
    const sudoPath = resolveSudoBinary();
    const toolPath = findSystemTool(toolName);
    if (!sudoPath || !toolPath || !canPasswordlessSudo()) {
        throw Object.assign(new Error(`Permission denied accessing root-owned path (run HKVM as root or enable passwordless sudo).`), { code: 'EACCES' });
    }
    for (const a of args) {
        if (typeof a !== 'string' || a.includes('\0')) {
            throw new Error('Invalid helper argument.');
        }
    }
    return (0, child_process_1.execFileSync)(sudoPath, ['-n', '--', toolPath, ...args], {
        input,
        stdio: ['pipe', 'pipe', 'pipe'],
        timeout: 15_000,
        maxBuffer: 16 * 1024 * 1024,
    });
}
/**
 * Narrow, `shell: false` filesystem helpers that use native Node `fs` first and transparently
 * fall back to `sudo -n` ONLY when accessing root-owned host paths (`/var/lib/lxc`, `/var/log/lxc`)
 * from a non-root panel process.
 */
exports.privilegedFs = {
    existsSync(targetPath) {
        const resolved = assertSafeFsPath(targetPath);
        try {
            fs_1.default.accessSync(resolved, fs_1.default.constants.F_OK);
            return true;
        }
        catch (err) {
            if (!isPermissionError(err))
                return false;
            if (!canPasswordlessSudo())
                return false;
            try {
                runSudoHelperSync('test', ['-e', resolved]);
                return true;
            }
            catch {
                return false;
            }
        }
    },
    realpathSync(targetPath) {
        const resolved = assertSafeFsPath(targetPath);
        try {
            return fs_1.default.realpathSync(resolved);
        }
        catch (err) {
            if (!isPermissionError(err) || !canPasswordlessSudo())
                throw err;
            const out = runSudoHelperSync('realpath', ['-e', '--', resolved]);
            return out.toString('utf8').replace(/\r?\n$/, '');
        }
    },
    mkdirpSync(targetPath, mode) {
        const resolved = assertSafeFsPath(targetPath);
        try {
            fs_1.default.mkdirSync(resolved, { recursive: true, ...(mode !== undefined ? { mode } : {}) });
        }
        catch (err) {
            if (!isPermissionError(err) || !canPasswordlessSudo())
                throw err;
            runSudoHelperSync('mkdir', ['-p', '--', resolved]);
            if (mode !== undefined) {
                runSudoHelperSync('chmod', [mode.toString(8), '--', resolved]);
            }
        }
    },
    rmdirSync(targetPath) {
        const resolved = assertSafeFsPath(targetPath);
        try {
            fs_1.default.rmdirSync(resolved);
        }
        catch (err) {
            if (err && err.code === 'ENOENT')
                return;
            if (!isPermissionError(err) || !canPasswordlessSudo())
                throw err;
            runSudoHelperSync('rmdir', ['--', resolved]);
        }
    },
    readFileSync(targetPath, maxBytes = 8 * 1024 * 1024) {
        const resolved = assertSafeFsPath(targetPath);
        try {
            const st = fs_1.default.lstatSync(resolved);
            if (st.size > maxBytes) {
                throw new Error(`File exceeds maximum read size (${maxBytes} bytes).`);
            }
            return fs_1.default.readFileSync(resolved);
        }
        catch (err) {
            if (!isPermissionError(err) || !canPasswordlessSudo())
                throw err;
            const buf = runSudoHelperSync('cat', ['--', resolved]);
            if (buf.length > maxBytes) {
                throw new Error(`File exceeds maximum read size (${maxBytes} bytes).`);
            }
            return buf;
        }
    },
    readTextSync(targetPath) {
        return exports.privilegedFs.readFileSync(targetPath).toString('utf8');
    },
    writeFileSync(targetPath, data, mode) {
        const resolved = assertSafeFsPath(targetPath);
        try {
            fs_1.default.writeFileSync(resolved, data, mode !== undefined ? { mode } : undefined);
        }
        catch (err) {
            if (!isPermissionError(err) || !canPasswordlessSudo())
                throw err;
            runSudoHelperSync('tee', ['--', resolved], data);
            if (mode !== undefined) {
                runSudoHelperSync('chmod', [mode.toString(8), '--', resolved]);
            }
        }
    },
    unlinkSync(targetPath) {
        const resolved = assertSafeFsPath(targetPath);
        try {
            fs_1.default.unlinkSync(resolved);
        }
        catch (err) {
            if (err && err.code === 'ENOENT')
                return;
            if (!isPermissionError(err) || !canPasswordlessSudo())
                throw err;
            runSudoHelperSync('rm', ['-f', '--', resolved]);
        }
    },
    renameSync(srcPath, destPath) {
        const srcResolved = assertSafeFsPath(srcPath);
        const destResolved = assertSafeFsPath(destPath);
        try {
            fs_1.default.renameSync(srcResolved, destResolved);
        }
        catch (err) {
            if (!isPermissionError(err) || !canPasswordlessSudo())
                throw err;
            runSudoHelperSync('mv', ['-T', '--', srcResolved, destResolved]);
        }
    },
    lstatMetaSync(targetPath) {
        const resolved = assertSafeFsPath(targetPath);
        try {
            const st = fs_1.default.lstatSync(resolved);
            return {
                isFile: st.isFile(),
                isDirectory: st.isDirectory(),
                isSymbolicLink: st.isSymbolicLink(),
                size: st.size,
                mtimeIso: st.mtime.toISOString(),
            };
        }
        catch (err) {
            if (!isPermissionError(err) || !canPasswordlessSudo())
                throw err;
            const out = runSudoHelperSync('stat', ['-c', '%F|%s|%Y', '--', resolved])
                .toString('utf8')
                .trim();
            const [typeStr, sizeStr, epochStr] = out.split('|');
            const lower = (typeStr || '').toLowerCase();
            const epochSec = parseInt(epochStr || '0', 10) || 0;
            return {
                isFile: lower.includes('regular file') || lower.includes('regular empty file'),
                isDirectory: lower.includes('directory'),
                isSymbolicLink: lower.includes('symbolic link'),
                size: parseInt(sizeStr || '0', 10) || 0,
                mtimeIso: new Date(epochSec * 1000).toISOString(),
            };
        }
    },
    readdirNamesSync(targetPath) {
        const resolved = assertSafeFsPath(targetPath);
        try {
            return fs_1.default.readdirSync(resolved);
        }
        catch (err) {
            if (!isPermissionError(err) || !canPasswordlessSudo())
                throw err;
            const out = runSudoHelperSync('ls', ['-1A', '--', resolved]).toString('utf8');
            return out.split('\n').filter(Boolean);
        }
    },
    rmRecursiveSync(targetPath) {
        const resolved = assertSafeFsPath(targetPath);
        if (resolved === '/' || resolved === '/var' || resolved === '/var/lib' || resolved === '/var/lib/lxc') {
            throw new Error(`Refusing to recursively remove protected system path: ${resolved}`);
        }
        try {
            fs_1.default.rmSync(resolved, { recursive: true, force: false });
        }
        catch (err) {
            if (!isPermissionError(err) || !canPasswordlessSudo())
                throw err;
            runSudoHelperSync('rm', ['-rf', '--', resolved]);
        }
    },
    chownToCurrentUserSync(targetPath) {
        if (isRunningAsRoot() || !canPasswordlessSudo())
            return;
        const resolved = assertSafeFsPath(targetPath);
        const uid = typeof process.getuid === 'function' ? process.getuid() : -1;
        const gid = typeof process.getgid === 'function' ? process.getgid() : -1;
        if (uid >= 0 && gid >= 0) {
            try {
                runSudoHelperSync('chown', [`${uid}:${gid}`, '--', resolved]);
            }
            catch {
                // best-effort ownership normalization for backup archives
            }
        }
    },
};
async function detectHostCapabilities() {
    const kvmDevicePresent = fs_1.default.existsSync('/dev/kvm');
    const qemuSystemAvailable = isBinaryAvailable('qemu-system-x86_64') || isBinaryAvailable('qemu-system-aarch64');
    const qemuImgAvailable = isBinaryAvailable('qemu-img');
    const lxcCreateAvailable = isBinaryAvailable('lxc-create');
    const lxcStartAvailable = isBinaryAvailable('lxc-start');
    const lxcInfoAvailable = isBinaryAvailable('lxc-info');
    let cgroupVersion = 0;
    if (fs_1.default.existsSync('/sys/fs/cgroup/cgroup.controllers')) {
        cgroupVersion = 2;
    }
    else if (fs_1.default.existsSync('/sys/fs/cgroup/memory') || fs_1.default.existsSync('/sys/fs/cgroup/cpu')) {
        cgroupVersion = 1;
    }
    const storageBackends = ['dir', 'raw'];
    if (isBinaryAvailable('mkfs.ext4') && isBinaryAvailable('mount'))
        storageBackends.push('loop');
    if (qemuImgAvailable)
        storageBackends.push('qcow2');
    if (isBinaryAvailable('lvs'))
        storageBackends.push('lvm', 'lvm-thin');
    if (isBinaryAvailable('zfs'))
        storageBackends.push('zfs');
    if (isBinaryAvailable('btrfs'))
        storageBackends.push('btrfs');
    const networkBackends = [];
    if (isBinaryAvailable('ip'))
        networkBackends.push('iproute2', 'bridge', 'vlan');
    if (isBinaryAvailable('iptables'))
        networkBackends.push('iptables', 'nat');
    if (isBinaryAvailable('nft'))
        networkBackends.push('nftables');
    if (isBinaryAvailable('tc'))
        networkBackends.push('tc-qos');
    let qemuVersion = null;
    if (isBinaryAvailable('qemu-system-x86_64')) {
        const res = await runAllowlistedCommand('qemu-system-x86_64', ['--version'], { timeoutMs: 5000 });
        if (res.exitCode === 0) {
            qemuVersion = res.stdout.split('\n')[0]?.trim() || null;
        }
    }
    let lxcVersion = null;
    if (lxcInfoAvailable) {
        const res = await runAllowlistedCommand('lxc-info', ['--version'], { timeoutMs: 5000 });
        if (res.exitCode === 0) {
            lxcVersion = res.stdout.trim() || null;
        }
    }
    const unameRes = await runAllowlistedCommand('uname', ['-r'], { timeoutMs: 3000 });
    const archRes = await runAllowlistedCommand('uname', ['-m'], { timeoutMs: 3000 });
    const lxcfsAvailable = isBinaryAvailable('lxcfs');
    let lxcfsMounted = false;
    try {
        lxcfsMounted = fs_1.default.existsSync('/var/lib/lxcfs/proc/meminfo');
    }
    catch {
        lxcfsMounted = false;
    }
    return {
        kvmDevicePresent,
        qemuSystemAvailable,
        qemuImgAvailable,
        kvmAvailable: qemuSystemAvailable && qemuImgAvailable,
        lxcCreateAvailable,
        lxcStartAvailable,
        lxcInfoAvailable,
        lxcAvailable: lxcCreateAvailable && lxcStartAvailable && lxcInfoAvailable,
        lxcfsAvailable,
        lxcfsMounted,
        cgroupVersion,
        storageBackends,
        networkBackends,
        qemuVersion,
        lxcVersion,
        kernelVersion: unameRes.stdout.trim() || process.platform,
        architecture: archRes.stdout.trim() || process.arch,
    };
}
/**
 * Parses `/proc/mounts` to locate an active mountpoint matching `targetDir`.
 * Returns the mounted device/source (e.g. `/dev/loop0`) or `null` if not mounted.
 */
function findActiveMountSource(targetDir) {
    try {
        if (!fs_1.default.existsSync('/proc/mounts'))
            return null;
        const normalized = path_1.default.resolve(targetDir);
        let realTarget = normalized;
        try {
            realTarget = fs_1.default.realpathSync(normalized);
        }
        catch {
            // target may require root or not exist yet
        }
        const raw = fs_1.default.readFileSync('/proc/mounts', 'utf8');
        for (const line of raw.split('\n')) {
            if (!line)
                continue;
            const cols = line.split(' ');
            if (cols.length < 2)
                continue;
            const mntTarget = cols[1].replace(/\\040/g, ' ').replace(/\\011/g, '\t');
            if (mntTarget === normalized || mntTarget === realTarget) {
                return cols[0].replace(/\\040/g, ' ');
            }
        }
    }
    catch {
        // ignore
    }
    return null;
}
/**
 * Ensures the `lxcfs` FUSE daemon is mounted at `/var/lib/lxcfs` so guest `/proc/meminfo`,
 * `/proc/cpuinfo`, `/proc/stat`, `/proc/swaps`, and `/proc/uptime` accurately reflect
 * each LXC container's assigned cgroup RAM, Swap, and CPU cores (`free -h`, `neofetch`, `htop`).
 */
let lxcfsInitPromise = null;
async function ensureLxcfsDaemonMounted(mountPoint = '/var/lib/lxcfs') {
    const probeFile = path_1.default.join(mountPoint, 'proc', 'meminfo');
    try {
        fs_1.default.statSync(probeFile);
        return true;
    }
    catch (err) {
        // Recover stale dead FUSE mount ("Transport endpoint is not connected" / ENOTCONN)
        if (err?.code === 'ENOTCONN' || findActiveMountSource(mountPoint)) {
            await runAllowlistedCommand('umount', ['-l', mountPoint], {
                timeoutMs: 5000,
                asRoot: true,
            }).catch(() => undefined);
        }
    }
    if (lxcfsInitPromise)
        return lxcfsInitPromise;
    lxcfsInitPromise = (async () => {
        try {
            const lxcfsBin = resolveBinaryPath('lxcfs');
            if (!lxcfsBin || !fs_1.default.existsSync('/dev/fuse')) {
                return false;
            }
            const rootOk = isRunningAsRoot() || canPasswordlessSudo();
            if (!rootOk)
                return false;
            exports.privilegedFs.mkdirpSync(mountPoint, 0o755);
            const trySpawnDaemon = async (flagVariant) => {
                const spawnCmd = isRunningAsRoot() ? lxcfsBin : (resolveSudoBinary() || 'sudo');
                const spawnArgs = isRunningAsRoot()
                    ? [...flagVariant, mountPoint]
                    : ['-n', lxcfsBin, ...flagVariant, mountPoint];
                try {
                    const child = (0, child_process_1.spawn)(spawnCmd, spawnArgs, {
                        detached: true,
                        stdio: 'ignore',
                        env: buildSafeSpawnEnv(true),
                    });
                    child.on('error', () => undefined);
                    child.unref();
                }
                catch {
                    return false;
                }
                for (let i = 0; i < 16; i++) {
                    await new Promise((r) => setTimeout(r, 100));
                    try {
                        fs_1.default.statSync(probeFile);
                        return true;
                    }
                    catch {
                        // keep polling
                    }
                }
                return false;
            };
            for (const flags of [
                ['--enable-cfs', '--enable-pidfd', '-l'],
                ['--enable-cfs', '-l'],
                [],
            ]) {
                if (await trySpawnDaemon(flags)) {
                    return true;
                }
                await runAllowlistedCommand('umount', ['-l', mountPoint], {
                    timeoutMs: 3000,
                    asRoot: true,
                }).catch(() => undefined);
            }
            return false;
        }
        finally {
            lxcfsInitPromise = null;
        }
    })();
    return lxcfsInitPromise;
}
