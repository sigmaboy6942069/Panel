import { execFile, execFileSync, spawn } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

export interface CommandResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  durationMs: number;
}

export interface CommandOptions {
  timeoutMs?: number;
  maxOutputBytes?: number;
  stdinData?: string;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  /**
   * Request root execution (`sudo -n`) when the Node process is not already UID 0.
   * Automatically enabled for system-level LXC, firewall, and volume-manager binaries
   * unless explicitly set to `false`.
   */
  asRoot?: boolean;
}

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
export function isAllowlistedBinary(binaryName: string): boolean {
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

function findSystemTool(name: string): string | null {
  for (const dir of SEARCH_DIRS) {
    const candidate = path.join(dir, name);
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
      return candidate;
    } catch {
      // continue
    }
  }
  return null;
}

export function isRunningAsRoot(): boolean {
  return typeof process.getuid === 'function' && process.getuid() === 0;
}

export function currentUsername(): string {
  try {
    return os.userInfo().username || process.env.USER || 'non-root';
  } catch {
    return process.env.USER || 'non-root';
  }
}

export function currentHomedir(): string {
  try {
    const h = os.homedir();
    if (h && h !== '/') return h;
  } catch {
    // ignore
  }
  if (process.env.HOME && process.env.HOME !== '/') {
    return process.env.HOME;
  }
  return isRunningAsRoot() ? '/root' : '/tmp';
}

let cachedSudoState: { checked: boolean; available: boolean; sudoPath: string | null } = {
  checked: false,
  available: false,
  sudoPath: null,
};

export function resolveSudoBinary(): string | null {
  if (!cachedSudoState.checked) {
    canPasswordlessSudo();
  }
  return cachedSudoState.sudoPath;
}

/**
 * Checks once whether non-interactive passwordless `sudo -n` is available when HKVM
 * is started as a non-root user (e.g., `ubuntu` or `codespace` running `npm start`).
 */
export function canPasswordlessSudo(): boolean {
  if (isRunningAsRoot()) return false;
  if (cachedSudoState.checked) return cachedSudoState.available;

  const sudoPath = findSystemTool('sudo');
  if (!sudoPath) {
    cachedSudoState = { checked: true, available: false, sudoPath: null };
    return false;
  }

  try {
    execFileSync(sudoPath, ['-n', 'true'], {
      stdio: 'ignore',
      timeout: 3000,
    });
    cachedSudoState = { checked: true, available: true, sudoPath };
    return true;
  } catch {
    cachedSudoState = { checked: true, available: false, sudoPath };
    return false;
  }
}

export function buildSafeSpawnEnv(
  effectiveRoot: boolean,
  extraEnv?: NodeJS.ProcessEnv
): Record<string, string> {
  const baseHome = effectiveRoot ? '/root' : currentHomedir();
  const baseUser = effectiveRoot ? 'root' : currentUsername();
  const merged: Record<string, string> = {
    PATH: SEARCH_DIRS.join(':'),
    HOME: baseHome,
    USER: baseUser,
    LOGNAME: baseUser,
    LANG: 'C.UTF-8',
    LC_ALL: 'C.UTF-8',
  };

  if (extraEnv) {
    for (const [k, v] of Object.entries(extraEnv)) {
      if (
        typeof v === 'string' &&
        /^[A-Za-z_][A-Za-z0-9_]*$/.test(k) &&
        !k.includes('\0') &&
        !v.includes('\0') &&
        !v.includes('\n')
      ) {
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

export function resolveBinaryPath(binaryName: string): string | null {
  const clean = path.basename(binaryName);
  if (!ALLOWED_BINARIES.has(clean)) {
    throw new Error(`Security policy violation: binary "${binaryName}" is not in the allowlist.`);
  }
  return findSystemTool(clean);
}

export function isBinaryAvailable(binaryName: string): boolean {
  try {
    return resolveBinaryPath(binaryName) !== null;
  } catch {
    return false;
  }
}

function isPureVersionProbe(args: string[]): boolean {
  return args.length === 1 && (args[0] === '--version' || args[0] === '-v' || args[0] === '-V');
}

/**
 * Safely executes an allowlisted binary with `shell: false`, optional stdin pipe,
 * controlled `sudo -n` elevation for privileged host tools, valid `HOME` env,
 * hard timeout, and bounded stdout/stderr buffers.
 */
export async function runAllowlistedCommand(
  binaryName: string,
  args: string[] = [],
  options: CommandOptions = {}
): Promise<CommandResult> {
  const cleanName = path.basename(binaryName);
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

  const wantsRoot =
    options.asRoot !== undefined
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
    } else {
      spawnArgs = ['-n', '--', resolved, ...args];
    }
  }

  const timeoutMs = options.timeoutMs ?? 60_000;
  const maxBytes = options.maxOutputBytes ?? 4 * 1024 * 1024;
  const startedAt = Date.now();

  return new Promise<CommandResult>((resolve) => {
    const child = spawn(spawnExecutable, spawnArgs, {
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
      } catch {
        // ignore
      }
    }, timeoutMs);

    child.stdout.on('data', (chunk: Buffer) => {
      if (stdoutBuf.length < maxBytes) {
        stdoutBuf += chunk.toString('utf8').slice(0, maxBytes - stdoutBuf.length);
      }
    });

    child.stderr.on('data', (chunk: Buffer) => {
      if (stderrBuf.length < maxBytes) {
        stderrBuf += chunk.toString('utf8').slice(0, maxBytes - stderrBuf.length);
      }
    });

    child.on('error', (err) => {
      if (settled) return;
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
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      const finalCode = code ?? (timedOut ? 124 : 1);
      let finalStderr = stderrBuf;
      if (
        finalCode !== 0 &&
        wantsRoot &&
        !effectiveRoot &&
        /permission denied|operation not permitted|must be root|not permitted/i.test(
          `${stderrBuf}\n${stdoutBuf}`
        )
      ) {
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

function isPermissionError(err: unknown): boolean {
  const code = (err as NodeJS.ErrnoException | undefined)?.code;
  return code === 'EACCES' || code === 'EPERM';
}

function assertSafeFsPath(targetPath: string): string {
  if (!targetPath || typeof targetPath !== 'string' || targetPath.includes('\0')) {
    throw new Error('Invalid filesystem path.');
  }
  return path.resolve(targetPath);
}

function runSudoHelperSync(toolName: string, args: string[], input?: Buffer | string): Buffer {
  const sudoPath = resolveSudoBinary();
  const toolPath = findSystemTool(toolName);
  if (!sudoPath || !toolPath || !canPasswordlessSudo()) {
    throw Object.assign(
      new Error(
        `Permission denied accessing root-owned path (run HKVM as root or enable passwordless sudo).`
      ),
      { code: 'EACCES' }
    );
  }
  for (const a of args) {
    if (typeof a !== 'string' || a.includes('\0')) {
      throw new Error('Invalid helper argument.');
    }
  }
  return execFileSync(sudoPath, ['-n', '--', toolPath, ...args], {
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
export const privilegedFs = {
  existsSync(targetPath: string): boolean {
    const resolved = assertSafeFsPath(targetPath);
    try {
      fs.accessSync(resolved, fs.constants.F_OK);
      return true;
    } catch (err) {
      if (!isPermissionError(err)) return false;
      if (!canPasswordlessSudo()) return false;
      try {
        runSudoHelperSync('test', ['-e', resolved]);
        return true;
      } catch {
        return false;
      }
    }
  },

  realpathSync(targetPath: string): string {
    const resolved = assertSafeFsPath(targetPath);
    try {
      return fs.realpathSync(resolved);
    } catch (err) {
      if (!isPermissionError(err) || !canPasswordlessSudo()) throw err;
      const out = runSudoHelperSync('realpath', ['-e', '--', resolved]);
      return out.toString('utf8').replace(/\r?\n$/, '');
    }
  },

  mkdirpSync(targetPath: string, mode?: number): void {
    const resolved = assertSafeFsPath(targetPath);
    try {
      fs.mkdirSync(resolved, { recursive: true, ...(mode !== undefined ? { mode } : {}) });
    } catch (err) {
      if (!isPermissionError(err) || !canPasswordlessSudo()) throw err;
      runSudoHelperSync('mkdir', ['-p', '--', resolved]);
      if (mode !== undefined) {
        runSudoHelperSync('chmod', [mode.toString(8), '--', resolved]);
      }
    }
  },

  rmdirSync(targetPath: string): void {
    const resolved = assertSafeFsPath(targetPath);
    try {
      fs.rmdirSync(resolved);
    } catch (err: any) {
      if (err && err.code === 'ENOENT') return;
      if (!isPermissionError(err) || !canPasswordlessSudo()) throw err;
      runSudoHelperSync('rmdir', ['--', resolved]);
    }
  },

  readFileSync(targetPath: string, maxBytes = 8 * 1024 * 1024): Buffer {
    const resolved = assertSafeFsPath(targetPath);
    try {
      const st = fs.lstatSync(resolved);
      if (st.size > maxBytes) {
        throw new Error(`File exceeds maximum read size (${maxBytes} bytes).`);
      }
      return fs.readFileSync(resolved);
    } catch (err) {
      if (!isPermissionError(err) || !canPasswordlessSudo()) throw err;
      const buf = runSudoHelperSync('cat', ['--', resolved]);
      if (buf.length > maxBytes) {
        throw new Error(`File exceeds maximum read size (${maxBytes} bytes).`);
      }
      return buf;
    }
  },

  readTextSync(targetPath: string): string {
    return privilegedFs.readFileSync(targetPath).toString('utf8');
  },

  writeFileSync(targetPath: string, data: Buffer | string, mode?: number): void {
    const resolved = assertSafeFsPath(targetPath);
    try {
      fs.writeFileSync(resolved, data, mode !== undefined ? { mode } : undefined);
    } catch (err) {
      if (!isPermissionError(err) || !canPasswordlessSudo()) throw err;
      runSudoHelperSync('tee', ['--', resolved], data);
      if (mode !== undefined) {
        runSudoHelperSync('chmod', [mode.toString(8), '--', resolved]);
      }
    }
  },

  unlinkSync(targetPath: string): void {
    const resolved = assertSafeFsPath(targetPath);
    try {
      fs.unlinkSync(resolved);
    } catch (err: any) {
      if (err && err.code === 'ENOENT') return;
      if (!isPermissionError(err) || !canPasswordlessSudo()) throw err;
      runSudoHelperSync('rm', ['-f', '--', resolved]);
    }
  },

  renameSync(srcPath: string, destPath: string): void {
    const srcResolved = assertSafeFsPath(srcPath);
    const destResolved = assertSafeFsPath(destPath);
    try {
      fs.renameSync(srcResolved, destResolved);
    } catch (err) {
      if (!isPermissionError(err) || !canPasswordlessSudo()) throw err;
      runSudoHelperSync('mv', ['-T', '--', srcResolved, destResolved]);
    }
  },

  lstatMetaSync(targetPath: string): {
    isFile: boolean;
    isDirectory: boolean;
    isSymbolicLink: boolean;
    size: number;
    mtimeIso: string;
  } {
    const resolved = assertSafeFsPath(targetPath);
    try {
      const st = fs.lstatSync(resolved);
      return {
        isFile: st.isFile(),
        isDirectory: st.isDirectory(),
        isSymbolicLink: st.isSymbolicLink(),
        size: st.size,
        mtimeIso: st.mtime.toISOString(),
      };
    } catch (err) {
      if (!isPermissionError(err) || !canPasswordlessSudo()) throw err;
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

  readdirNamesSync(targetPath: string): string[] {
    const resolved = assertSafeFsPath(targetPath);
    try {
      return fs.readdirSync(resolved);
    } catch (err) {
      if (!isPermissionError(err) || !canPasswordlessSudo()) throw err;
      const out = runSudoHelperSync('ls', ['-1A', '--', resolved]).toString('utf8');
      return out.split('\n').filter(Boolean);
    }
  },

  rmRecursiveSync(targetPath: string): void {
    const resolved = assertSafeFsPath(targetPath);
    if (resolved === '/' || resolved === '/var' || resolved === '/var/lib' || resolved === '/var/lib/lxc') {
      throw new Error(`Refusing to recursively remove protected system path: ${resolved}`);
    }
    try {
      fs.rmSync(resolved, { recursive: true, force: false });
    } catch (err) {
      if (!isPermissionError(err) || !canPasswordlessSudo()) throw err;
      runSudoHelperSync('rm', ['-rf', '--', resolved]);
    }
  },

  chownToCurrentUserSync(targetPath: string): void {
    if (isRunningAsRoot() || !canPasswordlessSudo()) return;
    const resolved = assertSafeFsPath(targetPath);
    const uid = typeof process.getuid === 'function' ? process.getuid() : -1;
    const gid = typeof process.getgid === 'function' ? process.getgid() : -1;
    if (uid >= 0 && gid >= 0) {
      try {
        runSudoHelperSync('chown', [`${uid}:${gid}`, '--', resolved]);
      } catch {
        // best-effort ownership normalization for backup archives
      }
    }
  },
};

export interface HostCapabilities {
  kvmDevicePresent: boolean;
  qemuSystemAvailable: boolean;
  qemuImgAvailable: boolean;
  kvmAvailable: boolean;
  lxcCreateAvailable: boolean;
  lxcStartAvailable: boolean;
  lxcInfoAvailable: boolean;
  lxcAvailable: boolean;
  lxcfsAvailable?: boolean;
  lxcfsMounted?: boolean;
  cgroupVersion: 1 | 2 | 0;
  storageBackends: string[];
  networkBackends: string[];
  qemuVersion: string | null;
  lxcVersion: string | null;
  kernelVersion: string;
  architecture: string;
}

export async function detectHostCapabilities(): Promise<HostCapabilities> {
  const kvmDevicePresent = fs.existsSync('/dev/kvm');
  const qemuSystemAvailable =
    isBinaryAvailable('qemu-system-x86_64') || isBinaryAvailable('qemu-system-aarch64');
  const qemuImgAvailable = isBinaryAvailable('qemu-img');
  const lxcCreateAvailable = isBinaryAvailable('lxc-create');
  const lxcStartAvailable = isBinaryAvailable('lxc-start');
  const lxcInfoAvailable = isBinaryAvailable('lxc-info');

  let cgroupVersion: 1 | 2 | 0 = 0;
  if (fs.existsSync('/sys/fs/cgroup/cgroup.controllers')) {
    cgroupVersion = 2;
  } else if (fs.existsSync('/sys/fs/cgroup/memory') || fs.existsSync('/sys/fs/cgroup/cpu')) {
    cgroupVersion = 1;
  }

  const storageBackends: string[] = ['dir', 'raw'];
  if (isBinaryAvailable('mkfs.ext4') && isBinaryAvailable('mount')) storageBackends.push('loop');
  if (qemuImgAvailable) storageBackends.push('qcow2');
  if (isBinaryAvailable('lvs')) storageBackends.push('lvm', 'lvm-thin');
  if (isBinaryAvailable('zfs')) storageBackends.push('zfs');
  if (isBinaryAvailable('btrfs')) storageBackends.push('btrfs');

  const networkBackends: string[] = [];
  if (isBinaryAvailable('ip')) networkBackends.push('iproute2', 'bridge', 'vlan');
  if (isBinaryAvailable('iptables')) networkBackends.push('iptables', 'nat');
  if (isBinaryAvailable('nft')) networkBackends.push('nftables');
  if (isBinaryAvailable('tc')) networkBackends.push('tc-qos');

  let qemuVersion: string | null = null;
  if (isBinaryAvailable('qemu-system-x86_64')) {
    const res = await runAllowlistedCommand('qemu-system-x86_64', ['--version'], { timeoutMs: 5000 });
    if (res.exitCode === 0) {
      qemuVersion = res.stdout.split('\n')[0]?.trim() || null;
    }
  }

  let lxcVersion: string | null = null;
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
    lxcfsMounted = fs.existsSync('/var/lib/lxcfs/proc/meminfo');
  } catch {
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
export function findActiveMountSource(targetDir: string): string | null {
  try {
    if (!fs.existsSync('/proc/mounts')) return null;
    const normalized = path.resolve(targetDir);
    let realTarget = normalized;
    try {
      realTarget = fs.realpathSync(normalized);
    } catch {
      // target may require root or not exist yet
    }
    const raw = fs.readFileSync('/proc/mounts', 'utf8');
    for (const line of raw.split('\n')) {
      if (!line) continue;
      const cols = line.split(' ');
      if (cols.length < 2) continue;
      const mntTarget = cols[1].replace(/\\040/g, ' ').replace(/\\011/g, '\t');
      if (mntTarget === normalized || mntTarget === realTarget) {
        return cols[0].replace(/\\040/g, ' ');
      }
    }
  } catch {
    // ignore
  }
  return null;
}

/**
 * Ensures the `lxcfs` FUSE daemon is mounted at `/var/lib/lxcfs` so guest `/proc/meminfo`,
 * `/proc/cpuinfo`, `/proc/stat`, `/proc/swaps`, and `/proc/uptime` accurately reflect
 * each LXC container's assigned cgroup RAM, Swap, and CPU cores (`free -h`, `neofetch`, `htop`).
 */
let lxcfsInitPromise: Promise<boolean> | null = null;

export async function ensureLxcfsDaemonMounted(mountPoint = '/var/lib/lxcfs'): Promise<boolean> {
  const probeFile = path.join(mountPoint, 'proc', 'meminfo');
  try {
    fs.statSync(probeFile);
    return true;
  } catch (err: any) {
    // Recover stale dead FUSE mount ("Transport endpoint is not connected" / ENOTCONN)
    if (err?.code === 'ENOTCONN' || findActiveMountSource(mountPoint)) {
      await runAllowlistedCommand('umount', ['-l', mountPoint], {
        timeoutMs: 5000,
        asRoot: true,
      }).catch(() => undefined);
    }
  }

  if (lxcfsInitPromise) return lxcfsInitPromise;

  lxcfsInitPromise = (async () => {
    try {
      const lxcfsBin = resolveBinaryPath('lxcfs');
      if (!lxcfsBin || !fs.existsSync('/dev/fuse')) {
        return false;
      }
      const rootOk = isRunningAsRoot() || canPasswordlessSudo();
      if (!rootOk) return false;

      privilegedFs.mkdirpSync(mountPoint, 0o755);

      const trySpawnDaemon = async (flagVariant: string[]): Promise<boolean> => {
        const spawnCmd = isRunningAsRoot() ? lxcfsBin : (resolveSudoBinary() || 'sudo');
        const spawnArgs = isRunningAsRoot()
          ? [...flagVariant, mountPoint]
          : ['-n', lxcfsBin, ...flagVariant, mountPoint];
        try {
          const child = spawn(spawnCmd, spawnArgs, {
            detached: true,
            stdio: 'ignore',
            env: buildSafeSpawnEnv(true),
          });
          child.on('error', () => undefined);
          child.unref();
        } catch {
          return false;
        }

        for (let i = 0; i < 16; i++) {
          await new Promise((r) => setTimeout(r, 100));
          try {
            fs.statSync(probeFile);
            return true;
          } catch {
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
    } finally {
      lxcfsInitPromise = null;
    }
  })();

  return lxcfsInitPromise;
}

// Keep unused execFile imported cleanly if needed by callers
export { execFile };
