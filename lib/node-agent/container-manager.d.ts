export interface LxcCreateSpec {
    containerName: string;
    hostname?: string;
    distro: string;
    release: string;
    fallbackRelease?: string | null;
    arch?: string;
    templateArchivePath?: string | null;
    cpuCores: number;
    cpuShares?: number;
    cpuLimitPercent?: number;
    cpuPinning?: string | null;
    ramMb: number;
    swapMb?: number;
    diskGb: number;
    backingStore?: 'dir' | 'loop' | 'lvm' | 'zfs' | 'btrfs';
    privileged?: boolean;
    nesting?: boolean;
    kvmNesting?: boolean;
    apparmorProfile?: string;
    bridge?: string;
    ipv4Address?: string | null;
    ipv4Gateway?: string | null;
    ipv6Address?: string | null;
    macAddress?: string | null;
    vlanId?: number | null;
    rootPassword?: string;
    sshPublicKeys?: string[];
    autostart?: boolean;
    mounts?: Array<{
        hostSource: string;
        guestTarget: string;
        readOnly?: boolean;
    }>;
    /**
     * When true (set by LXCAdapter when the panel database has no record for this container),
     * any stale/orphaned `/var/lib/lxc/<name>` directory from an earlier interrupted run is
     * cleanly destroyed and replaced instead of failing with "already exists on host".
     */
    replaceOrphanOnHost?: boolean;
}
export interface LxcResourceUpdateSpec {
    cpuCores?: number;
    cpuShares?: number;
    cpuLimitPercent?: number;
    cpuPinning?: string | null;
    ramMb?: number;
    swapMb?: number;
    diskGb?: number;
    nesting?: boolean;
    kvmNesting?: boolean;
    privileged?: boolean;
    apparmorProfile?: string;
    autostart?: boolean;
    bridge?: string;
    ipv4Address?: string | null;
    ipv4Gateway?: string | null;
    ipv6Address?: string | null;
}
export interface LxcContainerRuntimeInfo {
    name: string;
    state: 'running' | 'stopped' | 'frozen' | 'missing';
    pid: number | null;
    ips: string[];
    cpuUseSeconds: number;
    cpuCoresUsed?: number;
    memoryBytes: number;
    swapBytes: number;
    rxBytes: number;
    txBytes: number;
    diskUsedBytes: number;
    backingStore?: string;
    diskQuotaEnforced?: boolean;
    configuredIpv4?: string | null;
    configuredGateway?: string | null;
    startupWarning?: string;
}
export interface LxcBridgeNetworkInfo {
    ready: boolean;
    bridgeIp: string | null;
    prefixLen: number;
    subnetCidr: string | null;
    hasDhcpServer: boolean;
    natConfigured: boolean;
    dnsRelayPort: number;
}
export interface LxcNetworkRepairResult {
    containerName: string;
    state: LxcContainerRuntimeInfo['state'];
    bridge: string;
    ipv4Address: string | null;
    gateway: string | null;
    dnsServers: string[];
    dnsRelayPort?: number;
    natConfigured: boolean;
    liveApplied: boolean;
    restartedForVeth?: boolean;
}
export declare function ipv4ToUint32(ip: string): number;
export declare function uint32ToIpv4(num: number): string;
export declare function prefixLenToNetmask(prefixLen: number): string;
export declare function computeIpv4SubnetCidr(ip: string, prefixLen?: number): string | null;
/**
 * Resolves up to 3 reliable upstream IPv4 DNS servers suitable for inside an LXC container
 * (respecting glibc MAXNS=3 while filtering out host loopback 127.0.0.53 and WSL2's
 * non-bridge-routable 10.255.255.254 tunnel listener).
 */
export declare function resolveGuestDnsServers(hostResolvConfContent?: string): string[];
/**
 * Translates human/LXD version identifiers (e.g. `ubuntu` + `24.04` or `debian` + `12`)
 * into canonical `images.linuxcontainers.org` release names expected by `lxc-create -t download`
 * (`noble`, `bookworm`, `current`, etc.), while retaining fallbacks.
 */
export declare function resolveDownloadReleaseCandidates(rawDistro: string, rawRelease: string, fallbackRelease?: string | null): {
    distro: string;
    releases: string[];
    archMapper: (arch: string) => string;
};
export declare function isAppArmorProfileLoadable(): boolean;
/**
 * Parses Linux CPU list syntax (e.g. `"0-3"`, `"0,2-3,6"`) into sorted unique CPU IDs.
 */
export declare function parseCpuListSpec(spec: string): number[];
export declare function readEffectiveHostCpuIds(): number[];
/**
 * Deterministically assigns `requestedCores` distinct online host CPUs to `containerName`
 * (or honors `explicitPinning`), ensuring `nproc`, `lscpu`, and `neofetch` inside the guest
 * report the container's assigned vCPU count while spreading load across host cores.
 */
export declare function selectContainerCpuset(containerName: string, requestedCores: number, availableCpus?: number[], explicitPinning?: string | null): string | null;
/**
 * Resolves the host's base cgroup v2 directory from `/proc/1/cgroup`, stripping `/init.scope`
 * (and any legacy `/hkvm.host` leaf created by older builds) so `liblxc` and `lxcfs`
 * (`prune_init_scope()`) both resolve container cgroups from the same delegated root.
 */
export declare function resolveHostBaseCgroupV2Dir(proc1CgroupRaw?: string): string;
export declare function readCgroupV2Type(cgDir: string): string;
export declare function isUsableDomainCgroupDir(cgDir: string): boolean;
export declare function cleanupLegacyHostLeafCgroup(baseDir?: string): void;
/**
 * Ensures all available cgroup v2 controllers (`cpuset`, `cpu`, `io`, `memory`, `hugetlb`, `pids`,
 * `rdma`, `misc`, etc.) are delegated in BOTH `<baseCgroup>/cgroup.subtree_control` AND
 * `<baseCgroup>/hkvm.lxc/cgroup.subtree_control`.
 *
 * CRITICAL LINUX KERNEL CGROUP V2 RULES (`kernel/cgroup/cgroup.c` & `liblxc` `cgfsng.c`):
 * 1. Both `liblxc` and `lxcfs` read `/proc/1/cgroup` and call `prune_init_scope()`, which ONLY strips
 *    `/init.scope`. Host processes in `<baseDir>/cgroup.procs` MUST be evacuated into `<baseDir>/init.scope`.
 * 2. Inside a cgroup namespace (Docker, LXD, Codespaces, nested container hosts), `<baseDir>` is NOT
 *    the kernel's global mixable root (`!cgroup_is_mixable(baseDir)`). Enabling threaded-capable
 *    controllers (`+cpu`, `+cpuset`, `+pids`) while `<baseDir>/cgroup.procs` STILL contains tasks
 *    immediately flips `<baseDir>/cgroup.type` to `"domain threaded"`, causing `<baseDir>/init.scope`,
 *    `<baseDir>/hkvm.lxc`, and `lxc.monitor.<name>` to become `"domain invalid"` and fail with
 *    `-EOPNOTSUPP` ("Operation not supported") in `__cgfsng_delegate_controllers` and `cgfsng_monitor_enter`!
 * 3. Therefore:
 *    - If `<baseDir>` is `"domain threaded"` (or a non-root cgroup holding tasks while controllers are
 *      enabled), first disable controllers (`-<ctrl>`) on empty child cgroups and on `<baseDir>` so
 *      `<baseDir>` returns to `"domain"` and `<baseDir>/init.scope` returns to `"domain"`.
 *    - ALWAYS evacuate `<baseDir>/cgroup.procs` into `<baseDir>/init.scope/cgroup.procs` BEFORE enabling
 *      any controller on `<baseDir>/cgroup.subtree_control`.
 *    - Delegate ALL available controllers listed in `cgroup.controllers` (domain controllers first,
 *      threaded-capable controllers second) on BOTH `<baseDir>` and `<baseDir>/hkvm.lxc`, matching
 *      `liblxc`'s `__cgfsng_delegate_controllers()`.
 */
export declare function ensureCgroupV2SubtreeDelegation(targetBaseDir?: string): void;
export declare function resolveLiveContainerCgroupV2Dir(pid: number | null | undefined): string | null;
/**
 * Resolves a running container's root payload cgroup v2 directory (e.g.
 * `/sys/fs/cgroup/hkvm.lxc/lxc.payload.<name>`), stripping nested guest `systemd`
 * child cgroups such as `/init.scope` so `cpu.stat`, `memory.current`, `memory.max`,
 * and `cpu.max` reflect the entire container (`init.scope` + `system.slice` + `user.slice`
 * + nested Docker) rather than only idle PID 1. Returns `null` if the container shares
 * the host/daemon cgroup on an undelegated host.
 */
export declare function resolveContainerPayloadCgroupV2Dir(containerName: string, pid?: number | null): string | null;
/**
 * Reads high-resolution kernel CPU & memory accounting directly from cgroup v2 (`cpu.stat`
 * `usage_usec`, `memory.current`, `memory.swap.current`) or cgroup v1 (`cpuacct.usage`,
 * `memory.usage_in_bytes`). Works on both LXC 5.x (where `lxc-info` ignores cgroup v2
 * `cpu.stat` & `memory.current`) and LXC 6.x (avoiding `lxc-info`'s 32-bit `strtof` `%.2f`
 * precision loss).
 */
export declare function readContainerCgroupResourceStats(containerName: string, pid?: number | null): {
    cpuUseSeconds: number | null;
    memoryBytes: number | null;
    swapBytes: number | null;
    source: 'cgroup-v2' | 'cgroup-v1' | null;
};
export declare class LxcContainerManager {
    private lxcBaseDir;
    private inFlightCreations;
    private prevCpuSamples;
    constructor(lxcBaseDir?: string);
    isCreationInFlight(containerName: string): boolean;
    getBaseDir(): string;
    getContainerDir(containerName: string): string;
    getRootfsDir(containerName: string): string;
    /**
     * Determines whether operations against `this.lxcBaseDir` require root (`sudo -n`).
     * System `/var/lib/lxc` requires root, whereas unprivileged temporary directories in tests do not.
     */
    needsRootForStore(): boolean;
    private lxcPathArgs;
    private assertLxcInstalled;
    private ensureHostLxcDirectories;
    private isSystemLxcStore;
    private bridgeHasPhysicalSlave;
    private detectBridgeDhcpServer;
    private ensureIptablesRule;
    /**
     * Ensures the Linux bridge exists, is UP, has an IPv4 gateway address (when operating as
     * a virtual NAT bridge such as `lxcbr0`), starts HKVM's host-side `BridgeDnsRelay`, enables
     * kernel forwarding/rp_filter sysctls, and installs idempotent MASQUERADE, FORWARD ACCEPT,
     * INPUT ACCEPT, TCPMSS clamping, and PREROUTING DNS REDIRECT rules across BOTH `iptables`
     * and `iptables-legacy` (preventing WSL2 / Docker Desktop / UFW split-brain packet drops).
     */
    ensureBridgeNetworkReady(bridgeName: string): Promise<LxcBridgeNetworkInfo>;
    /**
     * Allocates a deterministic, collision-free IPv4 address from the bridge subnet when
     * no DHCP daemon (e.g. `dnsmasq`) is running on the bridge.
     */
    allocateAutoBridgeIpv4(containerName: string, bridgeName: string, bridgeIp: string, prefixLen?: number): Promise<string | null>;
    private resolveConfinedRootfsDir;
    /**
     * Configures guest DNS (`/etc/resolv.conf` + `systemd-resolved` drop-in) and guest
     * network manager config (`netplan`, `systemd-networkd`, `ifupdown`) strictly inside
     * the confined container rootfs so guest boot daemons never wipe liblxc's assigned IPv4
     * or point `/etc/resolv.conf` at a dead `127.0.0.53` stub.
     */
    configureGuestNetworkingAndDns(containerName: string, opts?: {
        ipv4Cidr?: string | null;
        gateway?: string | null;
        useDhcp?: boolean;
        dnsServers?: string[];
    }): string[];
    listContainers(): Promise<LxcContainerRuntimeInfo[]>;
    private readContainerNetFromConfig;
    inspectContainer(containerName: string, options?: {
        sampleCpu?: boolean;
    }): Promise<LxcContainerRuntimeInfo>;
    private readHighResContainerTelemetrySample;
    /**
     * Computes real-time active CPU cores utilized (`deltaCpuSec / deltaWallSec`) using the
     * host's monotonic clock. Performs a fast 120ms kernel cgroup/`/proc` micro-sample on
     * cold starts when `sampleIfCold` is enabled so opening an LXC VPS page immediately
     * displays live CPU Load instead of `0%`.
     */
    computeContainerCpuCoresUsed(safeName: string, pid: number | null, source: string, cpuSec1: number, monoMs1: number, sampleIfCold: boolean, readSecondSample?: () => {
        cpuUseSeconds: number;
        source: string;
        monoMs: number;
    }): Promise<number>;
    /**
     * Fallback live memory (VmRSS) & monotonic CPU time aggregator across `<initPid>` and all
     * its descendant processes in `/proc` for hosts (e.g. WSL2 / un-delegated cgroup v2) where
     * per-container cgroup accounting is unavailable. Includes `cutime + cstime` so reaped
     * short-lived child processes never make cumulative CPU ticks drop backwards.
     */
    measureContainerProcTree(rootPid: number): {
        memoryBytes: number;
        cpuUseSeconds: number;
    };
    private parseHumanSizeToBytes;
    private measureDirBytesFast;
    private getRootfsUsedBytes;
    getQuotaDiskDir(): string;
    getQuotaDiskImagePath(containerName: string): string;
    /**
     * Ensures an existing sparse `.ext4` quota volume is loop-mounted onto `<ctDir>/rootfs`
     * (for example after a host reboot before `lxc-start`).
     */
    ensureExistingQuotaDiskMounted(containerName: string): Promise<boolean>;
    /**
     * Unmounts `<ctDir>/rootfs` if backed by a loop mount, and optionally deletes the `.ext4` image.
     */
    unmountQuotaDiskIfMounted(containerName: string, removeImage?: boolean): Promise<void>;
    /**
     * Provisions or resizes a thin-provisioned sparse `ext4` loop quota volume mounted on `<ctDir>/rootfs`
     * so `df -h` inside the container reports the exact assigned `diskGb` (e.g. `20G`) and the kernel
     * enforces the hard block limit instead of exposing the entire host partition (`overlay 32G`).
     *
     * - Initial conversion is atomic: builds `.ext4.tmp` via `mkfs.ext4 -d <rootfs>`, probe-mounts on
     *   a temporary directory first to verify kernel loop-mount permission, and rolls back cleanly if
     *   loop mounting is unavailable.
     * - Online growth (`diskGb` increased while running) runs `truncate` + `losetup -c` + `resize2fs`
     *   with zero container downtime.
     */
    ensureContainerQuotaDisk(containerName: string, diskGb: number, options?: {
        allowNonSystemStore?: boolean;
    }): Promise<boolean>;
    private createFromLocalArchive;
    private applyOfflineRootPasswordHash;
    createContainer(spec: LxcCreateSpec): Promise<LxcContainerRuntimeInfo>;
    writeManagedConfigSection(containerName: string, cfg: {
        hostname?: string;
        cpuCores?: number;
        cpuShares?: number;
        cpuLimitPercent?: number;
        cpuPinning?: string | null;
        ramMb?: number;
        swapMb?: number;
        nesting?: boolean;
        kvmNesting?: boolean;
        privileged?: boolean;
        apparmorProfile?: string;
        autostart?: boolean;
        bridge?: string;
        ipv4Address?: string | null;
        ipv4Gateway?: string | null;
        ipv6Address?: string | null;
        macAddress?: string | null;
        mounts?: Array<{
            hostSource: string;
            guestTarget: string;
            readOnly?: boolean;
        }>;
    }): Promise<void>;
    private buildEffectiveGuestDnsList;
    private prepareContainerNetworkPreStart;
    /**
     * Ensures a running container's host-side `veth` peer is enslaved to `bridge` and `UP`
     * (recovers containers whose bridge was recreated or bounced while the container stayed running).
     */
    private ensureRunningVethAttachedToBridge;
    private applyLiveGuestNetworkIfNeeded;
    /**
     * Repairs host bridge/NAT/FORWARD/DNS-relay rules, upgrades `lxc.net.0.type = none` if needed,
     * auto-assigns a collision-free IPv4 if the container lacks one, re-enslaves orphaned host
     * `veth` peers (or restarts the container if `eth0` was never created), and applies IP/route/DNS
     * live inside the guest.
     */
    repairContainerNetworking(containerName: string, fallbackBridge?: string): Promise<LxcNetworkRepairResult>;
    ensureHostIsolationReady(): Promise<void>;
    parseManagedLimitsComment(configText: string): {
        ramMb?: number;
        swapMb?: number;
        cpuCores?: number;
        cpuLimitPercent?: number;
        cpuset?: string | null;
        cpuPinning?: string | null;
    } | null;
    /**
     * Enforces RAM (`memory.max`), Swap (`memory.swap.max`), CFS CPU quota (`cpu.max`), and
     * CPU core pinning (`cpuset.cpus`) directly on the running container's live kernel cgroup v2
     * directory (resolved from `/proc/<init_pid>/cgroup`), with each controller applied independently
     * so an unsupported secondary knob (such as `memory.swap.max` or `devices.allow`) NEVER prevents
     * `memory.max`, `cpu.max`, or `cpuset.cpus` from taking effect.
     */
    enforceLiveContainerCgroups(containerName: string, override?: {
        ramMb?: number;
        swapMb?: number;
        cpuCores?: number;
        cpuLimitPercent?: number;
        cpuPinning?: string | null;
        pid?: number | null;
        cgroupDirOverride?: string;
    }): Promise<boolean>;
    /**
     * Inspects both `<ct>/config` and the container's live kernel cgroup (`/proc/<pid>/cgroup`)
     * to determine whether the container needs its config refreshed, needs a restart out of an
     * undelegated cgroup (such as legacy `/hkvm.host/...`), or can have limits applied live in-place.
     */
    needsContainerCgroupRestartOrHeal(containerName: string, pid: number | null | undefined, desired: {
        ramMb: number;
        swapMb?: number;
        cpuCores: number;
        cpuLimitPercent?: number;
        cpuPinning?: string | null;
    }): {
        rewriteConfig: boolean;
        requiresRestart: boolean;
        enforceLive: boolean;
    };
    /**
     * Restores `lxc.cgroup.dir = hkvm.lxc` and `lxc.cgroup2.*` limit lines inside `<ct>/config`
     * when an earlier failed start stripped them prior to cgroup v2 `"domain threaded"` recovery.
     */
    restoreStrippedCgroupDirectivesIfReady(containerName: string): boolean;
    startContainer(containerName: string): Promise<void>;
    stopContainer(containerName: string, force?: boolean): Promise<void>;
    restartContainer(containerName: string): Promise<void>;
    freezeContainer(containerName: string): Promise<void>;
    unfreezeContainer(containerName: string): Promise<void>;
    destroyContainer(containerName: string): Promise<void>;
    reinstallContainer(spec: LxcCreateSpec): Promise<LxcContainerRuntimeInfo>;
    updateContainerResources(containerName: string, update: LxcResourceUpdateSpec): Promise<void>;
    /**
     * Resets root password inside container using `chpasswd` over stdin (`shell: false`),
     * with offline `/etc/shadow` SHA-512 hash fallback when container is stopped.
     * Zero shell interpolation of password characters.
     */
    setRootPassword(containerName: string, newPassword: string): Promise<void>;
    injectSshPublicKey(containerName: string, publicKey: string): Promise<void>;
    getContainerProcesses(containerName: string): Promise<Array<{
        pid: string;
        user: string;
        cpu: string;
        mem: string;
        command: string;
    }>>;
    getContainerLogs(containerName: string, maxLines?: number): Promise<string>;
    /**
     * Resolves a user-supplied path strictly within `<lxcBaseDir>/<container>/rootfs`,
     * blocking both `..` traversal and symlink escapes outside `rootfs`.
     */
    resolveConfinedRootfsPath(containerName: string, subPath: string): string;
    listRootfsDirectory(containerName: string, subPath?: string): Array<{
        name: string;
        path: string;
        isDirectory: boolean;
        size: number;
        modifiedAt: string;
    }>;
    readRootfsFile(containerName: string, subPath: string, maxBytes?: number): Buffer;
    writeRootfsFile(containerName: string, subPath: string, data: Buffer | string): void;
    deleteRootfsEntry(containerName: string, subPath: string): void;
}
