import { execFile } from 'child_process';
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
 * Binaries that manage system-wide hypervisor/container/network/volume state and require UID 0
 * when targeting host resources.
 */
export declare function isAllowlistedBinary(binaryName: string): boolean;
export declare function isRunningAsRoot(): boolean;
export declare function currentUsername(): string;
export declare function currentHomedir(): string;
export declare function resolveSudoBinary(): string | null;
/**
 * Checks once whether non-interactive passwordless `sudo -n` is available when HKVM
 * is started as a non-root user (e.g., `ubuntu` or `codespace` running `npm start`).
 */
export declare function canPasswordlessSudo(): boolean;
export declare function buildSafeSpawnEnv(effectiveRoot: boolean, extraEnv?: NodeJS.ProcessEnv): Record<string, string>;
export declare function resolveBinaryPath(binaryName: string): string | null;
export declare function isBinaryAvailable(binaryName: string): boolean;
/**
 * Safely executes an allowlisted binary with `shell: false`, optional stdin pipe,
 * controlled `sudo -n` elevation for privileged host tools, valid `HOME` env,
 * hard timeout, and bounded stdout/stderr buffers.
 */
export declare function runAllowlistedCommand(binaryName: string, args?: string[], options?: CommandOptions): Promise<CommandResult>;
/**
 * Narrow, `shell: false` filesystem helpers that use native Node `fs` first and transparently
 * fall back to `sudo -n` ONLY when accessing root-owned host paths (`/var/lib/lxc`, `/var/log/lxc`)
 * from a non-root panel process.
 */
export declare const privilegedFs: {
    existsSync(targetPath: string): boolean;
    realpathSync(targetPath: string): string;
    mkdirpSync(targetPath: string, mode?: number): void;
    rmdirSync(targetPath: string): void;
    readFileSync(targetPath: string, maxBytes?: number): Buffer;
    readTextSync(targetPath: string): string;
    writeFileSync(targetPath: string, data: Buffer | string, mode?: number): void;
    unlinkSync(targetPath: string): void;
    renameSync(srcPath: string, destPath: string): void;
    lstatMetaSync(targetPath: string): {
        isFile: boolean;
        isDirectory: boolean;
        isSymbolicLink: boolean;
        size: number;
        mtimeIso: string;
    };
    readdirNamesSync(targetPath: string): string[];
    rmRecursiveSync(targetPath: string): void;
    chownToCurrentUserSync(targetPath: string): void;
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
export declare function detectHostCapabilities(): Promise<HostCapabilities>;
/**
 * Parses `/proc/mounts` to locate an active mountpoint matching `targetDir`.
 * Returns the mounted device/source (e.g. `/dev/loop0`) or `null` if not mounted.
 */
export declare function findActiveMountSource(targetDir: string): string | null;
export declare function ensureLxcfsDaemonMounted(mountPoint?: string): Promise<boolean>;
export { execFile };
