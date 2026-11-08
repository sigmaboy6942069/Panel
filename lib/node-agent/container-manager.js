"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.LxcContainerManager = void 0;
exports.ipv4ToUint32 = ipv4ToUint32;
exports.uint32ToIpv4 = uint32ToIpv4;
exports.prefixLenToNetmask = prefixLenToNetmask;
exports.computeIpv4SubnetCidr = computeIpv4SubnetCidr;
exports.resolveGuestDnsServers = resolveGuestDnsServers;
exports.resolveDownloadReleaseCandidates = resolveDownloadReleaseCandidates;
exports.isAppArmorProfileLoadable = isAppArmorProfileLoadable;
exports.parseCpuListSpec = parseCpuListSpec;
exports.readEffectiveHostCpuIds = readEffectiveHostCpuIds;
exports.selectContainerCpuset = selectContainerCpuset;
exports.resolveHostBaseCgroupV2Dir = resolveHostBaseCgroupV2Dir;
exports.readCgroupV2Type = readCgroupV2Type;
exports.isUsableDomainCgroupDir = isUsableDomainCgroupDir;
exports.cleanupLegacyHostLeafCgroup = cleanupLegacyHostLeafCgroup;
exports.ensureCgroupV2SubtreeDelegation = ensureCgroupV2SubtreeDelegation;
exports.resolveLiveContainerCgroupV2Dir = resolveLiveContainerCgroupV2Dir;
exports.resolveContainerPayloadCgroupV2Dir = resolveContainerPayloadCgroupV2Dir;
exports.readContainerCgroupResourceStats = readContainerCgroupResourceStats;
const fs_1 = __importDefault(require("fs"));
const os_1 = __importDefault(require("os"));
const path_1 = __importDefault(require("path"));
const command_runner_1 = require("./command-runner");
const dns_relay_1 = require("./dns-relay");
const middleware_1 = require("../security/middleware");
function ipv4ToUint32(ip) {
    const parts = ip.trim().split('.').map((p) => parseInt(p, 10));
    if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
        return 0;
    }
    return (((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0);
}
function uint32ToIpv4(num) {
    const u = num >>> 0;
    return `${(u >>> 24) & 255}.${(u >>> 16) & 255}.${(u >>> 8) & 255}.${u & 255}`;
}
function prefixLenToNetmask(prefixLen) {
    const p = Math.min(32, Math.max(0, Math.floor(prefixLen)));
    const mask = p === 0 ? 0 : ((0xffffffff << (32 - p)) >>> 0);
    return uint32ToIpv4(mask);
}
function computeIpv4SubnetCidr(ip, prefixLen = 24) {
    const u = ipv4ToUint32(ip);
    if (!u)
        return null;
    const p = Math.min(32, Math.max(8, Math.floor(prefixLen)));
    const mask = (0xffffffff << (32 - p)) >>> 0;
    const net = (u & mask) >>> 0;
    return `${uint32ToIpv4(net)}/${p}`;
}
function isPrivateRfc1918Ipv4(ip) {
    const parts = ip.trim().split('.').map((p) => parseInt(p, 10));
    if (parts.length !== 4 || parts.some((n) => Number.isNaN(n)))
        return false;
    if (parts[0] === 10)
        return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31)
        return true;
    if (parts[0] === 192 && parts[1] === 168)
        return true;
    return false;
}
/**
 * Resolves up to 3 reliable upstream IPv4 DNS servers suitable for inside an LXC container
 * (respecting glibc MAXNS=3 while filtering out host loopback 127.0.0.53 and WSL2's
 * non-bridge-routable 10.255.255.254 tunnel listener).
 */
function resolveGuestDnsServers(hostResolvConfContent) {
    const envDns = (process.env.TGVPANEL_LXC_DNS || process.env.HKVM_LXC_DNS || '').trim();
    if (envDns) {
        const custom = envDns
            .split(/[\s,]+/)
            .map((s) => s.trim())
            .filter((s) => /^(\d{1,3}\.){3}\d{1,3}$/.test(s));
        if (custom.length > 0)
            return custom.slice(0, 3);
    }
    const hostCandidates = [];
    try {
        const raw = hostResolvConfContent !== undefined
            ? hostResolvConfContent
            : fs_1.default.existsSync('/etc/resolv.conf')
                ? fs_1.default.readFileSync('/etc/resolv.conf', 'utf8')
                : '';
        for (const line of raw.split('\n')) {
            const trimmed = line.trim();
            if (!trimmed || trimmed.startsWith('#'))
                continue;
            const m = trimmed.match(/^nameserver\s+(\d{1,3}(?:\.\d{1,3}){3})\b/i);
            if (!m)
                continue;
            const ns = m[1];
            if (ns.startsWith('127.') ||
                ns.startsWith('0.') ||
                ns.startsWith('169.254.') ||
                ns === '10.255.255.254') {
                continue;
            }
            if (!hostCandidates.includes(ns))
                hostCandidates.push(ns);
        }
    }
    catch {
        // ignore host /etc/resolv.conf read errors
    }
    const ordered = ['1.1.1.1', '8.8.8.8'];
    for (const h of hostCandidates) {
        if (!ordered.includes(h))
            ordered.push(h);
    }
    if (ordered.length < 3 && !ordered.includes('1.0.0.1')) {
        ordered.push('1.0.0.1');
    }
    return ordered.slice(0, 3);
}
const DEFAULT_LXC_BASE = process.env.TGVPANEL_LXC_PATH ||
    process.env.TGVPANEL_LXC_DIR ||
    process.env.HKVM_LXC_PATH ||
    '/var/lib/lxc';
const UBUNTU_RELEASE_MAP = {
    '18.04': 'bionic',
    '20.04': 'focal',
    '22.04': 'jammy',
    '24.04': 'noble',
    '24.10': 'oracular',
    '25.04': 'plucky',
    '25.10': 'questing',
    '26.04': 'resolute',
};
const DEBIAN_RELEASE_MAP = {
    '10': 'buster',
    '11': 'bullseye',
    '12': 'bookworm',
    '13': 'trixie',
    '14': 'forky',
};
const DEVUAN_RELEASE_MAP = {
    '4': 'chimaera',
    '5': 'daedalus',
};
/**
 * Translates human/LXD version identifiers (e.g. `ubuntu` + `24.04` or `debian` + `12`)
 * into canonical `images.linuxcontainers.org` release names expected by `lxc-create -t download`
 * (`noble`, `bookworm`, `current`, etc.), while retaining fallbacks.
 */
function resolveDownloadReleaseCandidates(rawDistro, rawRelease, fallbackRelease) {
    const distro = rawDistro.toLowerCase().replace(/[^a-z0-9_.-]/g, '') || 'ubuntu';
    const cleanRel = rawRelease.replace(/[^a-zA-Z0-9_.-]/g, '');
    const candidates = [];
    const pushUnique = (val) => {
        if (!val)
            return;
        const cleaned = val.replace(/[^a-zA-Z0-9_.-]/g, '');
        if (cleaned && !candidates.includes(cleaned)) {
            candidates.push(cleaned);
        }
    };
    if (distro === 'ubuntu') {
        if (UBUNTU_RELEASE_MAP[cleanRel]) {
            pushUnique(UBUNTU_RELEASE_MAP[cleanRel]);
        }
        pushUnique(cleanRel);
        for (const [ver, codename] of Object.entries(UBUNTU_RELEASE_MAP)) {
            if (codename === cleanRel.toLowerCase())
                pushUnique(ver);
        }
    }
    else if (distro === 'debian') {
        if (DEBIAN_RELEASE_MAP[cleanRel]) {
            pushUnique(DEBIAN_RELEASE_MAP[cleanRel]);
        }
        pushUnique(cleanRel);
        for (const [ver, codename] of Object.entries(DEBIAN_RELEASE_MAP)) {
            if (codename === cleanRel.toLowerCase())
                pushUnique(ver);
        }
    }
    else if (distro === 'devuan') {
        if (DEVUAN_RELEASE_MAP[cleanRel]) {
            pushUnique(DEVUAN_RELEASE_MAP[cleanRel]);
        }
        pushUnique(cleanRel);
    }
    else if (distro === 'kali' ||
        distro === 'archlinux' ||
        distro === 'voidlinux' ||
        distro === 'gentoo') {
        if (!cleanRel || cleanRel.toLowerCase() === 'rolling' || cleanRel.toLowerCase() === 'latest') {
            pushUnique('current');
        }
        pushUnique(cleanRel);
        pushUnique('current');
    }
    else if (distro === 'centos') {
        if (/^\d+$/.test(cleanRel)) {
            pushUnique(`${cleanRel}-Stream`);
        }
        pushUnique(cleanRel);
    }
    else {
        pushUnique(cleanRel);
    }
    if (fallbackRelease) {
        const fb = fallbackRelease.replace(/^images:[^/:]+[:/]/i, '');
        if (distro === 'ubuntu' && UBUNTU_RELEASE_MAP[fb])
            pushUnique(UBUNTU_RELEASE_MAP[fb]);
        if (distro === 'debian' && DEBIAN_RELEASE_MAP[fb])
            pushUnique(DEBIAN_RELEASE_MAP[fb]);
        pushUnique(fb);
    }
    if (candidates.length === 0) {
        candidates.push(distro === 'ubuntu' ? 'noble' : distro === 'debian' ? 'bookworm' : 'current');
    }
    return {
        distro,
        releases: candidates,
        archMapper: (rawArch) => {
            const a = (rawArch || 'amd64').toLowerCase().replace(/[^a-z0-9_.-]/g, '');
            if (a === 'x86_64' || a === 'x64')
                return 'amd64';
            if (a === 'aarch64')
                return 'arm64';
            return a || 'amd64';
        },
    };
}
function isAppArmorProfileLoadable() {
    try {
        if (!fs_1.default.existsSync('/sys/module/apparmor/parameters/enabled')) {
            return false;
        }
        const enabled = fs_1.default.readFileSync('/sys/module/apparmor/parameters/enabled', 'utf8').trim();
        if (enabled !== 'Y' && enabled !== '1') {
            return false;
        }
        return command_runner_1.privilegedFs.existsSync('/sys/kernel/security/apparmor/.load');
    }
    catch {
        return false;
    }
}
/**
 * Parses Linux CPU list syntax (e.g. `"0-3"`, `"0,2-3,6"`) into sorted unique CPU IDs.
 */
function parseCpuListSpec(spec) {
    const cpus = new Set();
    for (const part of String(spec || '').trim().split(',')) {
        const trimmed = part.trim();
        if (!trimmed)
            continue;
        const rangeMatch = trimmed.match(/^(\d+)-(\d+)$/);
        if (rangeMatch) {
            const start = parseInt(rangeMatch[1], 10);
            const end = parseInt(rangeMatch[2], 10);
            if (end >= start && end - start <= 1024) {
                for (let i = start; i <= end; i++)
                    cpus.add(i);
            }
        }
        else if (/^\d+$/.test(trimmed)) {
            cpus.add(parseInt(trimmed, 10));
        }
    }
    return Array.from(cpus).sort((a, b) => a - b);
}
function readEffectiveHostCpuIds() {
    try {
        for (const p of ['/sys/fs/cgroup/cpuset.cpus.effective', '/sys/fs/cgroup/cpuset/cpuset.cpus']) {
            if (fs_1.default.existsSync(p)) {
                const parsed = parseCpuListSpec(fs_1.default.readFileSync(p, 'utf8'));
                if (parsed.length > 0)
                    return parsed;
            }
        }
    }
    catch {
        // fallback to os.cpus()
    }
    const n = Math.max(1, os_1.default.cpus().length || 1);
    return Array.from({ length: n }, (_, idx) => idx);
}
/**
 * Deterministically assigns `requestedCores` distinct online host CPUs to `containerName`
 * (or honors `explicitPinning`), ensuring `nproc`, `lscpu`, and `neofetch` inside the guest
 * report the container's assigned vCPU count while spreading load across host cores.
 */
function selectContainerCpuset(containerName, requestedCores, availableCpus = readEffectiveHostCpuIds(), explicitPinning) {
    if (explicitPinning && /^[0-9,-]+$/.test(explicitPinning.trim())) {
        return explicitPinning.trim();
    }
    if (!availableCpus || availableCpus.length === 0)
        return null;
    const count = Math.max(1, Math.min(availableCpus.length, Math.floor(requestedCores || 1)));
    let hash = 2166136261;
    for (let i = 0; i < containerName.length; i++) {
        hash ^= containerName.charCodeAt(i);
        hash = Math.imul(hash, 16777619);
    }
    const start = (hash >>> 0) % availableCpus.length;
    const picked = [];
    for (let i = 0; i < count; i++) {
        picked.push(availableCpus[(start + i) % availableCpus.length]);
    }
    picked.sort((a, b) => a - b);
    return picked.join(',');
}
/**
 * Resolves the host's base cgroup v2 directory from `/proc/1/cgroup`, stripping `/init.scope`
 * (and any legacy `/hkvm.host` leaf created by older builds) so `liblxc` and `lxcfs`
 * (`prune_init_scope()`) both resolve container cgroups from the same delegated root.
 */
function resolveHostBaseCgroupV2Dir(proc1CgroupRaw) {
    try {
        const raw = proc1CgroupRaw !== undefined
            ? proc1CgroupRaw
            : fs_1.default.existsSync('/proc/1/cgroup')
                ? fs_1.default.readFileSync('/proc/1/cgroup', 'utf8')
                : '';
        for (const line of raw.split('\n')) {
            const trimmed = line.trim();
            if (!trimmed.startsWith('0::'))
                continue;
            let rel = trimmed.slice(3).trim() || '/';
            if (rel.endsWith('/init.scope')) {
                rel = rel.slice(0, -'/init.scope'.length) || '/';
            }
            else if (rel.endsWith('/hkvm.host')) {
                rel = rel.slice(0, -'/hkvm.host'.length) || '/';
            }
            const candidate = path_1.default.resolve('/sys/fs/cgroup', rel.replace(/^\/+/, ''));
            if (candidate.startsWith('/sys/fs/cgroup') && fs_1.default.existsSync(candidate)) {
                return candidate;
            }
        }
    }
    catch {
        // fallback to /sys/fs/cgroup
    }
    return '/sys/fs/cgroup';
}
function readCgroupV2Type(cgDir) {
    try {
        const typeFile = path_1.default.join(cgDir, 'cgroup.type');
        if (!fs_1.default.existsSync(typeFile)) {
            // Physical root `/sys/fs/cgroup` has CFTYPE_NOT_ON_ROOT on `cgroup.type` and is always a mixable domain
            return 'domain';
        }
        return fs_1.default.readFileSync(typeFile, 'utf8').trim() || 'domain';
    }
    catch {
        return 'domain';
    }
}
function isUsableDomainCgroupDir(cgDir) {
    if (!fs_1.default.existsSync(cgDir))
        return false;
    return readCgroupV2Type(cgDir) === 'domain';
}
const THREADED_CAPABLE_CONTROLLERS = new Set(['cpu', 'cpuset', 'pids', 'perf_event']);
function cleanupLegacyHostLeafCgroup(baseDir = resolveHostBaseCgroupV2Dir()) {
    try {
        const legacyLeaf = path_1.default.join(baseDir, 'hkvm.host');
        if (!fs_1.default.existsSync(legacyLeaf))
            return;
        const initScopeDir = path_1.default.join(baseDir, 'init.scope');
        command_runner_1.privilegedFs.mkdirpSync(initScopeDir);
        const legacyProcs = path_1.default.join(legacyLeaf, 'cgroup.procs');
        if (fs_1.default.existsSync(legacyProcs)) {
            const procsRaw = fs_1.default.readFileSync(legacyProcs, 'utf8');
            for (const pidLine of procsRaw.split('\n')) {
                const pid = pidLine.trim();
                if (!/^\d+$/.test(pid) || pid === '0')
                    continue;
                try {
                    command_runner_1.privilegedFs.writeFileSync(path_1.default.join(initScopeDir, 'cgroup.procs'), `${pid}\n`);
                }
                catch {
                    // exited process or kernel thread
                }
            }
        }
        try {
            command_runner_1.privilegedFs.rmdirSync(legacyLeaf);
        }
        catch {
            // non-empty or busy
        }
    }
    catch {
        // non-fatal
    }
}
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
function ensureCgroupV2SubtreeDelegation(targetBaseDir) {
    try {
        if (!fs_1.default.existsSync('/sys/fs/cgroup/cgroup.controllers') ||
            !fs_1.default.existsSync('/sys/fs/cgroup/cgroup.subtree_control')) {
            return;
        }
        if (!(0, command_runner_1.isRunningAsRoot)() && !(0, command_runner_1.canPasswordlessSudo)())
            return;
        const baseDir = targetBaseDir || resolveHostBaseCgroupV2Dir();
        const controllersFile = path_1.default.join(baseDir, 'cgroup.controllers');
        const subtreeFile = path_1.default.join(baseDir, 'cgroup.subtree_control');
        const procsFile = path_1.default.join(baseDir, 'cgroup.procs');
        if (!fs_1.default.existsSync(controllersFile) || !fs_1.default.existsSync(subtreeFile))
            return;
        const readTokens = (file) => fs_1.default.existsSync(file)
            ? fs_1.default.readFileSync(file, 'utf8').trim().split(/\s+/).filter(Boolean)
            : [];
        const readPids = (file) => readTokens(file).filter((p) => /^\d+$/.test(p) && p !== '0');
        const isNonPhysicalRoot = fs_1.default.existsSync(path_1.default.join(baseDir, 'cgroup.type'));
        let baseType = readCgroupV2Type(baseDir);
        let basePids = readPids(procsFile);
        let activeBaseSubtree = readTokens(subtreeFile);
        // Step 1: Self-heal `"domain threaded"` state on `baseDir` so child cgroups exit `"domain invalid"`!
        if (baseType === 'domain threaded' ||
            (isNonPhysicalRoot && basePids.length > 0 && activeBaseSubtree.length > 0)) {
            try {
                for (const entry of fs_1.default.readdirSync(baseDir, { withFileTypes: true })) {
                    if (!entry.isDirectory())
                        continue;
                    const childDir = path_1.default.join(baseDir, entry.name);
                    // Prune any empty leftover monitor/payload/legacy directories under `hkvm.lxc` or `baseDir`
                    if (entry.name === 'hkvm.lxc' && fs_1.default.existsSync(childDir)) {
                        for (const sub of fs_1.default.readdirSync(childDir, { withFileTypes: true })) {
                            if (!sub.isDirectory())
                                continue;
                            const subDir = path_1.default.join(childDir, sub.name);
                            if (readPids(path_1.default.join(subDir, 'cgroup.procs')).length === 0) {
                                try {
                                    command_runner_1.privilegedFs.rmdirSync(subDir);
                                }
                                catch {
                                    // busy
                                }
                            }
                        }
                    }
                    const childSub = path_1.default.join(childDir, 'cgroup.subtree_control');
                    if (fs_1.default.existsSync(childSub) && readPids(path_1.default.join(childDir, 'cgroup.procs')).length === 0) {
                        for (const c of readTokens(childSub)) {
                            try {
                                command_runner_1.privilegedFs.writeFileSync(childSub, `-${c}`);
                            }
                            catch {
                                // ignore
                            }
                        }
                    }
                    if (readCgroupV2Type(childDir) === 'threaded' &&
                        readTokens(path_1.default.join(childDir, 'cgroup.threads')).length === 0) {
                        try {
                            command_runner_1.privilegedFs.rmdirSync(childDir);
                        }
                        catch {
                            // ignore
                        }
                    }
                }
            }
            catch {
                // ignore child scan errors
            }
            for (const c of readTokens(subtreeFile)) {
                try {
                    command_runner_1.privilegedFs.writeFileSync(subtreeFile, `-${c}`);
                }
                catch {
                    // ignore if an active child cgroup holds controller
                }
            }
            baseType = readCgroupV2Type(baseDir);
        }
        // Step 2: Migrate any legacy `/hkvm.host` processes AND evacuate `<baseDir>/cgroup.procs`
        // into `<baseDir>/init.scope` BEFORE enabling any controller on `<baseDir>/cgroup.subtree_control`!
        cleanupLegacyHostLeafCgroup(baseDir);
        basePids = readPids(procsFile);
        if (basePids.length > 0) {
            const initScopeDir = path_1.default.join(baseDir, 'init.scope');
            command_runner_1.privilegedFs.mkdirpSync(initScopeDir);
            if (isUsableDomainCgroupDir(initScopeDir)) {
                for (const pid of basePids) {
                    try {
                        command_runner_1.privilegedFs.writeFileSync(path_1.default.join(initScopeDir, 'cgroup.procs'), `${pid}\n`);
                    }
                    catch {
                        // kernel thread on physical root or exited process
                    }
                }
            }
        }
        // Step 3: Order controllers so domain-only controllers (`memory`, `io`, `hugetlb`, `rdma`, `misc`)
        // are enabled BEFORE threaded-capable controllers (`cpuset`, `cpu`, `pids`, `perf_event`).
        const allAvailable = readTokens(controllersFile);
        const orderedControllers = [
            ...allAvailable.filter((c) => !THREADED_CAPABLE_CONTROLLERS.has(c)),
            ...allAvailable.filter((c) => THREADED_CAPABLE_CONTROLLERS.has(c)),
        ];
        const remainingBasePids = readPids(procsFile);
        const canEnableThreadedOnBase = !isNonPhysicalRoot || remainingBasePids.length === 0;
        activeBaseSubtree = readTokens(subtreeFile);
        const activeBaseSet = new Set(activeBaseSubtree);
        for (const c of orderedControllers) {
            if (activeBaseSet.has(c))
                continue;
            if (THREADED_CAPABLE_CONTROLLERS.has(c) && !canEnableThreadedOnBase) {
                // Never flip a non-mixable cgroup with remaining tasks into `"domain threaded"`!
                continue;
            }
            try {
                command_runner_1.privilegedFs.writeFileSync(subtreeFile, `+${c}`);
            }
            catch {
                // ignore unsupported individual controller
            }
        }
        // Step 4: Create dedicated container parent cgroup `<baseDir>/hkvm.lxc` (zero internal processes)
        // and delegate ALL available controllers on it so `liblxc`'s `__cgfsng_delegate_controllers()`
        // and `cgfsng_monitor_enter()` succeed and every `lxc.payload.<name>` child gets `memory.max`,
        // `memory.current`, `memory.stat`, `cpu.max`, and `cpuset.cpus`!
        const lxcGroupDir = path_1.default.join(baseDir, 'hkvm.lxc');
        command_runner_1.privilegedFs.mkdirpSync(lxcGroupDir);
        // Clean up any stale empty monitor/payload directories left by aborted starts
        try {
            for (const sub of fs_1.default.readdirSync(lxcGroupDir, { withFileTypes: true })) {
                if (!sub.isDirectory())
                    continue;
                const subDir = path_1.default.join(lxcGroupDir, sub.name);
                if (readPids(path_1.default.join(subDir, 'cgroup.procs')).length === 0) {
                    try {
                        command_runner_1.privilegedFs.rmdirSync(subDir);
                    }
                    catch {
                        // ignore
                    }
                }
            }
        }
        catch {
            // ignore
        }
        if (isUsableDomainCgroupDir(lxcGroupDir)) {
            const lxcGroupControllersFile = path_1.default.join(lxcGroupDir, 'cgroup.controllers');
            const lxcGroupSubtreeFile = path_1.default.join(lxcGroupDir, 'cgroup.subtree_control');
            const lxcProcsFile = path_1.default.join(lxcGroupDir, 'cgroup.procs');
            // If any stray PID ever landed directly inside `hkvm.lxc`, move it to `init.scope`
            for (const strayPid of readPids(lxcProcsFile)) {
                try {
                    const initScopeDir = path_1.default.join(baseDir, 'init.scope');
                    command_runner_1.privilegedFs.mkdirpSync(initScopeDir);
                    command_runner_1.privilegedFs.writeFileSync(path_1.default.join(initScopeDir, 'cgroup.procs'), `${strayPid}\n`);
                }
                catch {
                    // ignore
                }
            }
            if (fs_1.default.existsSync(lxcGroupControllersFile) && fs_1.default.existsSync(lxcGroupSubtreeFile)) {
                const lxcAvail = readTokens(lxcGroupControllersFile);
                const lxcOrdered = [
                    ...lxcAvail.filter((c) => !THREADED_CAPABLE_CONTROLLERS.has(c)),
                    ...lxcAvail.filter((c) => THREADED_CAPABLE_CONTROLLERS.has(c)),
                ];
                const lxcDelegated = new Set(readTokens(lxcGroupSubtreeFile));
                for (const c of lxcOrdered) {
                    if (lxcDelegated.has(c))
                        continue;
                    try {
                        command_runner_1.privilegedFs.writeFileSync(lxcGroupSubtreeFile, `+${c}`);
                    }
                    catch {
                        // ignore
                    }
                }
            }
        }
    }
    catch {
        // non-fatal on read-only cgroupfs
    }
}
function resolveLiveContainerCgroupV2Dir(pid) {
    try {
        if (!pid || pid <= 1)
            return null;
        const cgFile = `/proc/${pid}/cgroup`;
        let raw = '';
        if (fs_1.default.existsSync(cgFile)) {
            raw = fs_1.default.readFileSync(cgFile, 'utf8');
        }
        else if (command_runner_1.privilegedFs.existsSync(cgFile)) {
            raw = command_runner_1.privilegedFs.readTextSync(cgFile);
        }
        else {
            return null;
        }
        for (const line of raw.split('\n')) {
            const trimmed = line.trim();
            if (!trimmed.startsWith('0::'))
                continue;
            const rel = trimmed.slice(3).trim();
            if (!rel || rel === '/')
                return null;
            const candidate = path_1.default.resolve('/sys/fs/cgroup', rel.replace(/^\/+/, ''));
            if (candidate.startsWith('/sys/fs/cgroup/') && fs_1.default.existsSync(candidate)) {
                return candidate;
            }
        }
    }
    catch {
        // ignore
    }
    return null;
}
function isCgroupV2SubtreePopulated(cgDir) {
    try {
        const eventsFile = path_1.default.join(cgDir, 'cgroup.events');
        if (fs_1.default.existsSync(eventsFile)) {
            const txt = fs_1.default.readFileSync(eventsFile, 'utf8');
            const m = txt.match(/^populated\s+(\d+)/m);
            if (m)
                return m[1] !== '0';
        }
        const procsFile = path_1.default.join(cgDir, 'cgroup.procs');
        if (fs_1.default.existsSync(procsFile)) {
            return fs_1.default.readFileSync(procsFile, 'utf8').trim().length > 0;
        }
    }
    catch {
        // ignore
    }
    return false;
}
/**
 * Resolves a running container's root payload cgroup v2 directory (e.g.
 * `/sys/fs/cgroup/hkvm.lxc/lxc.payload.<name>`), stripping nested guest `systemd`
 * child cgroups such as `/init.scope` so `cpu.stat`, `memory.current`, `memory.max`,
 * and `cpu.max` reflect the entire container (`init.scope` + `system.slice` + `user.slice`
 * + nested Docker) rather than only idle PID 1. Returns `null` if the container shares
 * the host/daemon cgroup on an undelegated host.
 */
function resolveContainerPayloadCgroupV2Dir(containerName, pid) {
    try {
        if (!fs_1.default.existsSync('/sys/fs/cgroup/cgroup.controllers')) {
            return null;
        }
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        const hostBaseDir = resolveHostBaseCgroupV2Dir();
        const ownCgDir = resolveLiveContainerCgroupV2Dir(process.pid);
        const isSharedHostOrDaemonCgroup = (dir) => {
            if (dir === '/sys/fs/cgroup' ||
                dir === hostBaseDir ||
                dir === path_1.default.join(hostBaseDir, 'init.scope') ||
                dir === path_1.default.join(hostBaseDir, 'hkvm.host') ||
                dir === path_1.default.join(hostBaseDir, 'hkvm.lxc') ||
                dir === path_1.default.join(hostBaseDir, 'system.slice') ||
                dir === path_1.default.join(hostBaseDir, 'user.slice')) {
                return true;
            }
            if (ownCgDir && (dir === ownCgDir || ownCgDir.startsWith(dir + path_1.default.sep))) {
                return true;
            }
            return false;
        };
        if (pid && pid > 1) {
            const rawPidCg = resolveLiveContainerCgroupV2Dir(pid);
            if (rawPidCg) {
                if (isSharedHostOrDaemonCgroup(rawPidCg)) {
                    return null;
                }
                const relToRoot = path_1.default.relative('/sys/fs/cgroup', rawPidCg);
                const parts = relToRoot.split(path_1.default.sep).filter(Boolean);
                const payloadIdx = parts.findIndex((seg) => seg.startsWith('lxc.payload.'));
                let normalizedDir;
                if (payloadIdx !== -1) {
                    normalizedDir = path_1.default.join('/sys/fs/cgroup', ...parts.slice(0, payloadIdx + 1));
                }
                else if (parts.length > 1 && parts[parts.length - 1] === 'init.scope') {
                    normalizedDir = path_1.default.join('/sys/fs/cgroup', ...parts.slice(0, -1));
                }
                else {
                    normalizedDir = rawPidCg;
                }
                if (normalizedDir.startsWith('/sys/fs/cgroup/') &&
                    fs_1.default.existsSync(normalizedDir) &&
                    !isSharedHostOrDaemonCgroup(normalizedDir)) {
                    return normalizedDir;
                }
                return null;
            }
        }
        // Fallback when `/proc/<pid>/cgroup` is hidden (e.g. `hidepid=2` without root):
        // inspect known liblxc payload paths only if kernel `cgroup.events` reports `populated 1`.
        const directCandidates = [
            path_1.default.join(hostBaseDir, 'hkvm.lxc', `lxc.payload.${safeName}`),
            path_1.default.join(hostBaseDir, `lxc.payload.${safeName}`),
            path_1.default.join('/sys/fs/cgroup/hkvm.lxc', `lxc.payload.${safeName}`),
            path_1.default.join('/sys/fs/cgroup', `lxc.payload.${safeName}`),
            path_1.default.join('/sys/fs/cgroup/lxc', safeName),
        ];
        for (const cand of directCandidates) {
            if (fs_1.default.existsSync(cand) &&
                !isSharedHostOrDaemonCgroup(cand) &&
                isCgroupV2SubtreePopulated(cand)) {
                return cand;
            }
        }
        for (const parentDir of [path_1.default.join(hostBaseDir, 'hkvm.lxc'), hostBaseDir]) {
            if (!fs_1.default.existsSync(parentDir))
                continue;
            const prefix = `lxc.payload.${safeName}-`;
            for (const entry of fs_1.default.readdirSync(parentDir)) {
                if (!entry.startsWith(prefix))
                    continue;
                const cand = path_1.default.join(parentDir, entry);
                if (!isSharedHostOrDaemonCgroup(cand) && isCgroupV2SubtreePopulated(cand)) {
                    return cand;
                }
            }
        }
    }
    catch {
        // ignore
    }
    return null;
}
/**
 * Reads high-resolution kernel CPU & memory accounting directly from cgroup v2 (`cpu.stat`
 * `usage_usec`, `memory.current`, `memory.swap.current`) or cgroup v1 (`cpuacct.usage`,
 * `memory.usage_in_bytes`). Works on both LXC 5.x (where `lxc-info` ignores cgroup v2
 * `cpu.stat` & `memory.current`) and LXC 6.x (avoiding `lxc-info`'s 32-bit `strtof` `%.2f`
 * precision loss).
 */
function readContainerCgroupResourceStats(containerName, pid) {
    const safeName = middleware_1.SafeValidators.containerName(containerName);
    // 1. Cgroup v2 (`cpu.stat` -> `usage_usec` in microseconds)
    const cgV2Dir = resolveContainerPayloadCgroupV2Dir(safeName, pid);
    if (cgV2Dir) {
        let cpuUseSeconds = null;
        let memoryBytes = null;
        let swapBytes = null;
        try {
            const cpuStatFile = path_1.default.join(cgV2Dir, 'cpu.stat');
            if (fs_1.default.existsSync(cpuStatFile)) {
                const txt = fs_1.default.readFileSync(cpuStatFile, 'utf8');
                const usageMatch = txt.match(/^usage_usec\s+(\d+)/m);
                if (usageMatch) {
                    cpuUseSeconds = Number(BigInt(usageMatch[1])) / 1_000_000;
                }
                else {
                    const userMatch = txt.match(/^user_usec\s+(\d+)/m);
                    const sysMatch = txt.match(/^system_usec\s+(\d+)/m);
                    if (userMatch || sysMatch) {
                        const totalUsec = BigInt(userMatch ? userMatch[1] : '0') + BigInt(sysMatch ? sysMatch[1] : '0');
                        cpuUseSeconds = Number(totalUsec) / 1_000_000;
                    }
                }
            }
        }
        catch {
            // ignore
        }
        try {
            const memCurFile = path_1.default.join(cgV2Dir, 'memory.current');
            if (fs_1.default.existsSync(memCurFile)) {
                const rawCur = parseInt(fs_1.default.readFileSync(memCurFile, 'utf8').trim(), 10);
                if (!Number.isNaN(rawCur) && rawCur >= 0) {
                    let inactiveFile = 0;
                    const memStatFile = path_1.default.join(cgV2Dir, 'memory.stat');
                    if (fs_1.default.existsSync(memStatFile)) {
                        const statTxt = fs_1.default.readFileSync(memStatFile, 'utf8');
                        const inactMatch = statTxt.match(/^inactive_file\s+(\d+)/m);
                        if (inactMatch) {
                            inactiveFile = parseInt(inactMatch[1], 10) || 0;
                        }
                    }
                    memoryBytes = rawCur > inactiveFile ? rawCur - inactiveFile : rawCur;
                }
            }
        }
        catch {
            // ignore
        }
        try {
            const swapCurFile = path_1.default.join(cgV2Dir, 'memory.swap.current');
            if (fs_1.default.existsSync(swapCurFile)) {
                const rawSwap = parseInt(fs_1.default.readFileSync(swapCurFile, 'utf8').trim(), 10);
                if (!Number.isNaN(rawSwap) && rawSwap >= 0) {
                    swapBytes = rawSwap;
                }
            }
        }
        catch {
            // ignore
        }
        if (cpuUseSeconds !== null || memoryBytes !== null) {
            return { cpuUseSeconds, memoryBytes, swapBytes, source: 'cgroup-v2' };
        }
    }
    // 2. Cgroup v1 (`cpuacct.usage` in nanoseconds)
    try {
        const readPidCpuacctRel = (targetPid) => {
            const f = `/proc/${targetPid}/cgroup`;
            if (!fs_1.default.existsSync(f))
                return null;
            for (const line of fs_1.default.readFileSync(f, 'utf8').split('\n')) {
                const parts = line.trim().split(':');
                if (parts.length < 3)
                    continue;
                const ctrls = parts[1].split(',');
                if (ctrls.includes('cpuacct')) {
                    return parts.slice(2).join(':').trim();
                }
            }
            return null;
        };
        const v1Candidates = [];
        if (pid && pid > 1) {
            const pidRel = readPidCpuacctRel(pid);
            const selfRel = readPidCpuacctRel(process.pid);
            const initRel = readPidCpuacctRel(1);
            if (pidRel && pidRel !== '/' && pidRel !== selfRel && pidRel !== initRel) {
                const segs = pidRel.split('/').filter(Boolean);
                const payIdx = segs.findIndex((s) => s.startsWith('lxc.payload.'));
                const normRel = payIdx !== -1
                    ? segs.slice(0, payIdx + 1).join('/')
                    : segs.length > 1 && segs[segs.length - 1] === 'init.scope'
                        ? segs.slice(0, -1).join('/')
                        : segs.join('/');
                if (normRel && `/${normRel}` !== selfRel && `/${normRel}` !== initRel) {
                    v1Candidates.push(path_1.default.join('/sys/fs/cgroup/cpuacct', normRel), path_1.default.join('/sys/fs/cgroup/cpu,cpuacct', normRel));
                }
            }
        }
        else {
            for (const base of ['/sys/fs/cgroup/cpuacct', '/sys/fs/cgroup/cpu,cpuacct']) {
                v1Candidates.push(path_1.default.join(base, `lxc.payload.${safeName}`), path_1.default.join(base, 'lxc', safeName));
            }
        }
        for (const dir of v1Candidates) {
            const usageFile = path_1.default.join(dir, 'cpuacct.usage');
            if (!fs_1.default.existsSync(usageFile))
                continue;
            const rawNs = fs_1.default.readFileSync(usageFile, 'utf8').trim();
            if (/^\d+$/.test(rawNs)) {
                const cpuUseSeconds = Number(BigInt(rawNs)) / 1_000_000_000;
                return { cpuUseSeconds, memoryBytes: null, swapBytes: null, source: 'cgroup-v1' };
            }
        }
    }
    catch {
        // ignore
    }
    return { cpuUseSeconds: null, memoryBytes: null, swapBytes: null, source: null };
}
function readActiveCgroupV2Controllers(enableIfSystem = false) {
    try {
        if (!fs_1.default.existsSync('/sys/fs/cgroup/cgroup.controllers')) {
            return null;
        }
        if (enableIfSystem) {
            ensureCgroupV2SubtreeDelegation();
        }
        const baseDir = resolveHostBaseCgroupV2Dir();
        const lxcGroupDir = path_1.default.join(baseDir, 'hkvm.lxc');
        const lxcGroupSubtree = path_1.default.join(lxcGroupDir, 'cgroup.subtree_control');
        if (enableIfSystem && isUsableDomainCgroupDir(lxcGroupDir) && fs_1.default.existsSync(lxcGroupSubtree)) {
            const lxcSub = fs_1.default.readFileSync(lxcGroupSubtree, 'utf8').trim();
            const lxcDelegated = new Set(lxcSub.split(/\s+/).filter(Boolean));
            if (lxcDelegated.size > 0) {
                return lxcDelegated;
            }
        }
        const ctrlFile = path_1.default.join(baseDir, 'cgroup.controllers');
        const subFile = path_1.default.join(baseDir, 'cgroup.subtree_control');
        const raw = fs_1.default.readFileSync(fs_1.default.existsSync(ctrlFile) ? ctrlFile : '/sys/fs/cgroup/cgroup.controllers', 'utf8').trim();
        const rootControllers = new Set(raw.split(/\s+/).filter(Boolean));
        if (fs_1.default.existsSync(subFile) && isUsableDomainCgroupDir(baseDir)) {
            const subRaw = fs_1.default.readFileSync(subFile, 'utf8').trim();
            const delegated = new Set(subRaw.split(/\s+/).filter(Boolean));
            // On WSL2 / nested container hosts where root subtree_control has not delegated controllers,
            // writing lxc.cgroup2.<ctrl>.* causes lxc-start to fail with ENOENT on child cgroup files.
            return new Set([...rootControllers].filter((c) => delegated.has(c)));
        }
        return new Set();
    }
    catch {
        return null;
    }
}
function isCgroupV2SwapSupported() {
    if (fs_1.default.existsSync('/sys/fs/cgroup/memory.swap.max') ||
        fs_1.default.existsSync('/sys/fs/cgroup/init.scope/memory.swap.max') ||
        fs_1.default.existsSync('/sys/fs/cgroup/system.slice/memory.swap.max') ||
        fs_1.default.existsSync('/sys/fs/cgroup/hkvm.host/memory.swap.max')) {
        return true;
    }
    try {
        for (const entry of fs_1.default.readdirSync('/sys/fs/cgroup')) {
            if (fs_1.default.existsSync(path_1.default.join('/sys/fs/cgroup', entry, 'memory.swap.max'))) {
                return true;
            }
        }
    }
    catch {
        // ignore
    }
    return false;
}
class LxcContainerManager {
    lxcBaseDir;
    inFlightCreations = new Set();
    prevCpuSamples = new Map();
    constructor(lxcBaseDir = DEFAULT_LXC_BASE) {
        this.lxcBaseDir = path_1.default.resolve(lxcBaseDir);
    }
    isCreationInFlight(containerName) {
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        return this.inFlightCreations.has(safeName.toLowerCase());
    }
    getBaseDir() {
        return this.lxcBaseDir;
    }
    getContainerDir(containerName) {
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        return path_1.default.join(this.lxcBaseDir, safeName);
    }
    getRootfsDir(containerName) {
        return path_1.default.join(this.getContainerDir(containerName), 'rootfs');
    }
    /**
     * Determines whether operations against `this.lxcBaseDir` require root (`sudo -n`).
     * System `/var/lib/lxc` requires root, whereas unprivileged temporary directories in tests do not.
     */
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
            const parent = path_1.default.dirname(this.lxcBaseDir);
            fs_1.default.accessSync(parent, fs_1.default.constants.R_OK | fs_1.default.constants.W_OK | fs_1.default.constants.X_OK);
            return false;
        }
        catch {
            return true;
        }
    }
    lxcPathArgs() {
        return ['-P', this.lxcBaseDir];
    }
    assertLxcInstalled() {
        if (!(0, command_runner_1.isBinaryAvailable)('lxc-info') || !(0, command_runner_1.isBinaryAvailable)('lxc-create')) {
            throw new Error('LXC userland utilities (lxc-create / lxc-start / lxc-info) are not installed on this host.');
        }
    }
    ensureHostLxcDirectories() {
        command_runner_1.privilegedFs.mkdirpSync(this.lxcBaseDir, 0o755);
        if (this.lxcBaseDir === '/var/lib/lxc') {
            try {
                command_runner_1.privilegedFs.mkdirpSync('/var/cache/lxc', 0o755);
                command_runner_1.privilegedFs.mkdirpSync('/var/log/lxc', 0o755);
            }
            catch {
                // non-fatal if /var/log/lxc cannot be created
            }
        }
    }
    isSystemLxcStore() {
        return this.lxcBaseDir === '/var/lib/lxc' || this.lxcBaseDir.startsWith('/var/lib/lxc/');
    }
    bridgeHasPhysicalSlave(safeBridge) {
        try {
            const brifDir = `/sys/class/net/${safeBridge}/brif`;
            if (!fs_1.default.existsSync(brifDir))
                return false;
            for (const iface of fs_1.default.readdirSync(brifDir)) {
                if (fs_1.default.existsSync(`/sys/class/net/${iface}/device`)) {
                    return true;
                }
            }
            return false;
        }
        catch {
            return false;
        }
    }
    detectBridgeDhcpServer(safeBridge) {
        try {
            for (const pidFile of ['/run/lxc/dnsmasq.pid', '/var/run/lxc/dnsmasq.pid']) {
                if (safeBridge === 'lxcbr0' && fs_1.default.existsSync(pidFile)) {
                    const p = parseInt(fs_1.default.readFileSync(pidFile, 'utf8').trim(), 10);
                    if (p > 0 && fs_1.default.existsSync(`/proc/${p}`))
                        return true;
                }
            }
            if (!fs_1.default.existsSync('/proc'))
                return false;
            for (const ent of fs_1.default.readdirSync('/proc')) {
                if (!/^\d+$/.test(ent))
                    continue;
                try {
                    const cmd = fs_1.default.readFileSync(`/proc/${ent}/cmdline`, 'utf8').replace(/\0/g, ' ');
                    if (/(dnsmasq|dhcpd|kea-dhcp4|udhcpd)/i.test(cmd) &&
                        (cmd.includes(safeBridge) || (safeBridge === 'lxcbr0' && cmd.includes('lxc')))) {
                        return true;
                    }
                }
                catch {
                    // ignore exited proc
                }
            }
            return false;
        }
        catch {
            return false;
        }
    }
    async ensureIptablesRule(bin, table, chain, ruleArgs, insertTop = true) {
        const tblArgs = table === 'filter' ? [] : ['-t', table];
        const check = await (0, command_runner_1.runAllowlistedCommand)(bin, [...tblArgs, '-C', chain, ...ruleArgs], { timeoutMs: 4000, asRoot: true });
        if (check.exitCode === 0)
            return true;
        const addArgs = insertTop
            ? [...tblArgs, '-I', chain, '1', ...ruleArgs]
            : [...tblArgs, '-A', chain, ...ruleArgs];
        const add = await (0, command_runner_1.runAllowlistedCommand)(bin, addArgs, { timeoutMs: 4000, asRoot: true });
        return add.exitCode === 0;
    }
    /**
     * Ensures the Linux bridge exists, is UP, has an IPv4 gateway address (when operating as
     * a virtual NAT bridge such as `lxcbr0`), starts HKVM's host-side `BridgeDnsRelay`, enables
     * kernel forwarding/rp_filter sysctls, and installs idempotent MASQUERADE, FORWARD ACCEPT,
     * INPUT ACCEPT, TCPMSS clamping, and PREROUTING DNS REDIRECT rules across BOTH `iptables`
     * and `iptables-legacy` (preventing WSL2 / Docker Desktop / UFW split-brain packet drops).
     */
    async ensureBridgeNetworkReady(bridgeName) {
        const safeBridge = middleware_1.SafeValidators.bridgeOrIface(bridgeName);
        if (!(0, command_runner_1.isBinaryAvailable)('ip')) {
            return {
                ready: fs_1.default.existsSync(`/sys/class/net/${safeBridge}`),
                bridgeIp: null,
                prefixLen: 24,
                subnetCidr: null,
                hasDhcpServer: this.detectBridgeDhcpServer(safeBridge),
                natConfigured: false,
                dnsRelayPort: 0,
            };
        }
        if (!fs_1.default.existsSync(`/sys/class/net/${safeBridge}`)) {
            await (0, command_runner_1.runAllowlistedCommand)('ip', ['link', 'add', 'name', safeBridge, 'type', 'bridge'], {
                timeoutMs: 5000,
                asRoot: true,
            });
        }
        if (!fs_1.default.existsSync(`/sys/class/net/${safeBridge}`)) {
            return {
                ready: false,
                bridgeIp: null,
                prefixLen: 24,
                subnetCidr: null,
                hasDhcpServer: false,
                natConfigured: false,
                dnsRelayPort: 0,
            };
        }
        await (0, command_runner_1.runAllowlistedCommand)('ip', ['link', 'set', safeBridge, 'up'], {
            timeoutMs: 5000,
            asRoot: true,
        });
        let bridgeIp = null;
        let prefixLen = 24;
        const addrRes = await (0, command_runner_1.runAllowlistedCommand)('ip', ['-4', '-o', 'addr', 'show', 'dev', safeBridge], { timeoutMs: 5000, asRoot: true });
        const addrMatch = addrRes.stdout.match(/\binet\s+(\d+\.\d+\.\d+\.\d+)\/(\d+)\b/);
        if (addrMatch) {
            bridgeIp = addrMatch[1];
            prefixLen = parseInt(addrMatch[2], 10) || 24;
        }
        const isVirtualNatBridge = !this.bridgeHasPhysicalSlave(safeBridge);
        if (!bridgeIp && isVirtualNatBridge) {
            const routeRes = await (0, command_runner_1.runAllowlistedCommand)('ip', ['-4', 'route', 'show'], {
                timeoutMs: 5000,
            });
            const routesText = routeRes.stdout || '';
            const gatewayCandidates = ['10.0.3.1', '10.88.3.1', '10.99.3.1', '172.29.3.1'];
            let chosenGw = '10.0.3.1';
            for (const cand of gatewayCandidates) {
                const prefix3 = cand.split('.').slice(0, 3).join('.') + '.';
                if (!routesText.includes(prefix3)) {
                    chosenGw = cand;
                    break;
                }
            }
            const assignRes = await (0, command_runner_1.runAllowlistedCommand)('ip', ['addr', 'add', `${chosenGw}/24`, 'dev', safeBridge], { timeoutMs: 5000, asRoot: true });
            if (assignRes.exitCode === 0 || /File exists/i.test(assignRes.stderr)) {
                bridgeIp = chosenGw;
                prefixLen = 24;
            }
        }
        const subnetCidr = bridgeIp ? computeIpv4SubnetCidr(bridgeIp, prefixLen) : null;
        let natConfigured = false;
        let dnsRelayPort = 0;
        if (bridgeIp && subnetCidr && isVirtualNatBridge && isPrivateRfc1918Ipv4(bridgeIp)) {
            const dnsRelay = (0, dns_relay_1.getSharedBridgeDnsRelay)();
            dnsRelay.addExcludedLoopIp(bridgeIp);
            dnsRelayPort = await dnsRelay.ensureStarted().catch(() => 0);
            if ((0, command_runner_1.isBinaryAvailable)('modprobe')) {
                for (const mod of ['iptable_nat', 'nf_nat', 'xt_MASQUERADE', 'xt_REDIRECT', 'xt_TCPMSS']) {
                    await (0, command_runner_1.runAllowlistedCommand)('modprobe', [mod], {
                        timeoutMs: 3000,
                        asRoot: true,
                    }).catch(() => undefined);
                }
            }
            if ((0, command_runner_1.isBinaryAvailable)('sysctl')) {
                const sysctlKeys = [
                    'net.ipv4.ip_forward=1',
                    'net.ipv4.conf.all.forwarding=1',
                    'net.ipv4.conf.default.forwarding=1',
                    `net.ipv4.conf.${safeBridge}.forwarding=1`,
                    `net.ipv4.conf.${safeBridge}.rp_filter=0`,
                    'net.ipv4.conf.all.rp_filter=0',
                ];
                for (const kv of sysctlKeys) {
                    await (0, command_runner_1.runAllowlistedCommand)('sysctl', ['-w', kv], {
                        timeoutMs: 3000,
                        asRoot: true,
                    }).catch(() => undefined);
                }
            }
            // Program BOTH iptables (often iptables-nft) AND iptables-legacy if present on host:
            // on WSL2 + Docker Desktop / Ubuntu, Docker frequently sets `FORWARD DROP` in
            // iptables-legacy while `/usr/sbin/iptables` points to iptables-nft!
            const iptBins = [];
            if ((0, command_runner_1.isBinaryAvailable)('iptables'))
                iptBins.push('iptables');
            if ((0, command_runner_1.isBinaryAvailable)('iptables-legacy'))
                iptBins.push('iptables-legacy');
            for (const bin of iptBins) {
                const masqOk = await this.ensureIptablesRule(bin, 'nat', 'POSTROUTING', ['-s', subnetCidr, '!', '-d', subnetCidr, '-j', 'MASQUERADE'], true);
                if (masqOk)
                    natConfigured = true;
                // Top-of-chain FORWARD ACCEPT by both bridge device AND container CIDR (handles br_netfilter)
                await this.ensureIptablesRule(bin, 'filter', 'FORWARD', ['-i', safeBridge, '-j', 'ACCEPT'], true);
                await this.ensureIptablesRule(bin, 'filter', 'FORWARD', ['-o', safeBridge, '-j', 'ACCEPT'], true);
                await this.ensureIptablesRule(bin, 'filter', 'FORWARD', ['-s', subnetCidr, '-j', 'ACCEPT'], true);
                await this.ensureIptablesRule(bin, 'filter', 'FORWARD', ['-d', subnetCidr, '-j', 'ACCEPT'], true);
                // Clamp TCP MSS to path MTU (prevents `apt update` hanging at 0% [Working] on WSL2/PPPoE/Hotspot!)
                await this.ensureIptablesRule(bin, 'mangle', 'FORWARD', ['-i', safeBridge, '-p', 'tcp', '--tcp-flags', 'SYN,RST', 'SYN', '-j', 'TCPMSS', '--clamp-mss-to-pmtu'], true);
                await this.ensureIptablesRule(bin, 'mangle', 'FORWARD', ['-o', safeBridge, '-p', 'tcp', '--tcp-flags', 'SYN,RST', 'SYN', '-j', 'TCPMSS', '--clamp-mss-to-pmtu'], true);
                // Allow DHCP (67/68) and DNS (53 + dnsRelayPort) through host INPUT chain (UFW / INPUT DROP hosts)
                await this.ensureIptablesRule(bin, 'filter', 'INPUT', ['-i', safeBridge, '-p', 'udp', '--dport', '67', '-j', 'ACCEPT'], true);
                await this.ensureIptablesRule(bin, 'filter', 'INPUT', ['-s', subnetCidr, '-p', 'udp', '--dport', '53', '-j', 'ACCEPT'], true);
                await this.ensureIptablesRule(bin, 'filter', 'INPUT', ['-s', subnetCidr, '-p', 'tcp', '--dport', '53', '-j', 'ACCEPT'], true);
                if (dnsRelayPort > 0) {
                    await this.ensureIptablesRule(bin, 'filter', 'INPUT', ['-s', subnetCidr, '-p', 'udp', '--dport', String(dnsRelayPort), '-j', 'ACCEPT'], true);
                    await this.ensureIptablesRule(bin, 'filter', 'INPUT', ['-s', subnetCidr, '-p', 'tcp', '--dport', String(dnsRelayPort), '-j', 'ACCEPT'], true);
                    await this.ensureIptablesRule(bin, 'nat', 'PREROUTING', ['-s', subnetCidr, '-d', bridgeIp, '-p', 'udp', '--dport', '53', '-j', 'REDIRECT', '--to-ports', String(dnsRelayPort)], true);
                    await this.ensureIptablesRule(bin, 'nat', 'PREROUTING', ['-s', subnetCidr, '-d', bridgeIp, '-p', 'tcp', '--dport', '53', '-j', 'REDIRECT', '--to-ports', String(dnsRelayPort)], true);
                }
            }
            if (!natConfigured && (0, command_runner_1.isBinaryAvailable)('nft')) {
                await (0, command_runner_1.runAllowlistedCommand)('nft', ['add', 'table', 'ip', 'hkvm_lxc_nat'], {
                    timeoutMs: 5000,
                    asRoot: true,
                });
                await (0, command_runner_1.runAllowlistedCommand)('nft', [
                    'add',
                    'chain',
                    'ip',
                    'hkvm_lxc_nat',
                    'postrouting',
                    '{ type nat hook postrouting priority 100 ; }',
                ], { timeoutMs: 5000, asRoot: true });
                await (0, command_runner_1.runAllowlistedCommand)('nft', ['flush', 'chain', 'ip', 'hkvm_lxc_nat', 'postrouting'], {
                    timeoutMs: 5000,
                    asRoot: true,
                });
                const nftMasq = await (0, command_runner_1.runAllowlistedCommand)('nft', [
                    'add',
                    'rule',
                    'ip',
                    'hkvm_lxc_nat',
                    'postrouting',
                    'ip',
                    'saddr',
                    subnetCidr,
                    'ip',
                    'daddr',
                    '!=',
                    subnetCidr,
                    'masquerade',
                ], { timeoutMs: 5000, asRoot: true });
                await (0, command_runner_1.runAllowlistedCommand)('nft', [
                    'add',
                    'chain',
                    'ip',
                    'hkvm_lxc_nat',
                    'forward',
                    '{ type filter hook forward priority -10 ; policy accept ; }',
                ], { timeoutMs: 5000, asRoot: true });
                if (dnsRelayPort > 0) {
                    await (0, command_runner_1.runAllowlistedCommand)('nft', [
                        'add',
                        'chain',
                        'ip',
                        'hkvm_lxc_nat',
                        'prerouting',
                        '{ type nat hook prerouting priority -100 ; }',
                    ], { timeoutMs: 5000, asRoot: true });
                    await (0, command_runner_1.runAllowlistedCommand)('nft', ['flush', 'chain', 'ip', 'hkvm_lxc_nat', 'prerouting'], {
                        timeoutMs: 5000,
                        asRoot: true,
                    });
                    await (0, command_runner_1.runAllowlistedCommand)('nft', [
                        'add',
                        'rule',
                        'ip',
                        'hkvm_lxc_nat',
                        'prerouting',
                        'ip',
                        'saddr',
                        subnetCidr,
                        'ip',
                        'daddr',
                        bridgeIp,
                        'udp',
                        'dport',
                        '53',
                        'redirect',
                        'to',
                        `:${dnsRelayPort}`,
                    ], { timeoutMs: 5000, asRoot: true });
                    await (0, command_runner_1.runAllowlistedCommand)('nft', [
                        'add',
                        'rule',
                        'ip',
                        'hkvm_lxc_nat',
                        'prerouting',
                        'ip',
                        'saddr',
                        subnetCidr,
                        'ip',
                        'daddr',
                        bridgeIp,
                        'tcp',
                        'dport',
                        '53',
                        'redirect',
                        'to',
                        `:${dnsRelayPort}`,
                    ], { timeoutMs: 5000, asRoot: true });
                }
                natConfigured = nftMasq.exitCode === 0;
            }
        }
        return {
            ready: true,
            bridgeIp,
            prefixLen,
            subnetCidr,
            hasDhcpServer: this.detectBridgeDhcpServer(safeBridge),
            natConfigured,
            dnsRelayPort,
        };
    }
    /**
     * Allocates a deterministic, collision-free IPv4 address from the bridge subnet when
     * no DHCP daemon (e.g. `dnsmasq`) is running on the bridge.
     */
    async allocateAutoBridgeIpv4(containerName, bridgeName, bridgeIp, prefixLen = 24) {
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        const gwUint = ipv4ToUint32(bridgeIp);
        if (!gwUint || prefixLen < 16 || prefixLen > 29)
            return null;
        const mask = (0xffffffff << (32 - prefixLen)) >>> 0;
        const netBase = (gwUint & mask) >>> 0;
        const hostCount = (1 << (32 - prefixLen)) - 2;
        if (hostCount < 4)
            return null;
        const usedIps = new Set([bridgeIp]);
        // Scan existing container configs in lxcBaseDir
        try {
            if (command_runner_1.privilegedFs.existsSync(this.lxcBaseDir)) {
                for (const dirName of command_runner_1.privilegedFs.readdirNamesSync(this.lxcBaseDir)) {
                    const cfgPath = path_1.default.join(this.lxcBaseDir, dirName, 'config');
                    if (!command_runner_1.privilegedFs.existsSync(cfgPath))
                        continue;
                    try {
                        const txt = command_runner_1.privilegedFs.readTextSync(cfgPath);
                        const m = txt.match(/^\s*lxc\.net\.0\.ipv4\.address\s*=\s*(\d+\.\d+\.\d+\.\d+)(?:\/(\d+))?/m);
                        if (!m)
                            continue;
                        const ipOnly = m[1];
                        if (dirName === safeName) {
                            const candNet = (ipv4ToUint32(ipOnly) & mask) >>> 0;
                            if (candNet === netBase && ipOnly !== bridgeIp) {
                                return `${ipOnly}/${prefixLen}`;
                            }
                        }
                        else {
                            usedIps.add(ipOnly);
                        }
                    }
                    catch {
                        // ignore unreadable config
                    }
                }
            }
        }
        catch {
            // ignore scan failure
        }
        // Also avoid any active ARP neighbors on the bridge
        if ((0, command_runner_1.isBinaryAvailable)('ip') && this.isSystemLxcStore()) {
            const neighRes = await (0, command_runner_1.runAllowlistedCommand)('ip', ['-4', 'neigh', 'show', 'dev', middleware_1.SafeValidators.bridgeOrIface(bridgeName)], { timeoutMs: 4000 }).catch(() => null);
            if (neighRes && neighRes.stdout) {
                for (const line of neighRes.stdout.split('\n')) {
                    const m = line.trim().match(/^(\d+\.\d+\.\d+\.\d+)\b/);
                    if (m)
                        usedIps.add(m[1]);
                }
            }
        }
        const minHost = Math.min(100, Math.max(2, Math.floor(hostCount / 4)));
        const maxHost = Math.min(hostCount, 250);
        const poolSize = Math.max(1, maxHost - minHost + 1);
        let hash = 0;
        for (let i = 0; i < safeName.length; i++) {
            hash = (hash * 31 + safeName.charCodeAt(i)) >>> 0;
        }
        for (let i = 0; i < poolSize; i++) {
            const hostOffset = minHost + ((hash + i) % poolSize);
            const candidateIp = uint32ToIpv4((netBase + hostOffset) >>> 0);
            if (!usedIps.has(candidateIp)) {
                return `${candidateIp}/${prefixLen}`;
            }
        }
        for (let hostOffset = 2; hostOffset <= hostCount; hostOffset++) {
            const candidateIp = uint32ToIpv4((netBase + hostOffset) >>> 0);
            if (!usedIps.has(candidateIp)) {
                return `${candidateIp}/${prefixLen}`;
            }
        }
        return null;
    }
    resolveConfinedRootfsDir(containerName, relDir, createIfMissing = false) {
        const rootfs = path_1.default.resolve(this.getRootfsDir(containerName));
        if (!command_runner_1.privilegedFs.existsSync(rootfs))
            return null;
        const segments = relDir.split('/').filter(Boolean);
        let cur = rootfs;
        for (const seg of segments) {
            const next = path_1.default.join(cur, seg);
            if (!next.startsWith(rootfs + path_1.default.sep))
                return null;
            if (command_runner_1.privilegedFs.existsSync(next)) {
                const meta = command_runner_1.privilegedFs.lstatMetaSync(next);
                if (meta.isSymbolicLink || !meta.isDirectory) {
                    return null;
                }
            }
            else if (createIfMissing) {
                command_runner_1.privilegedFs.mkdirpSync(next, 0o755);
            }
            else {
                return null;
            }
            cur = next;
        }
        return cur;
    }
    /**
     * Configures guest DNS (`/etc/resolv.conf` + `systemd-resolved` drop-in) and guest
     * network manager config (`netplan`, `systemd-networkd`, `ifupdown`) strictly inside
     * the confined container rootfs so guest boot daemons never wipe liblxc's assigned IPv4
     * or point `/etc/resolv.conf` at a dead `127.0.0.53` stub.
     */
    configureGuestNetworkingAndDns(containerName, opts = {}) {
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        const dnsList = (opts.dnsServers && opts.dnsServers.length > 0
            ? opts.dnsServers
            : resolveGuestDnsServers()).slice(0, 3);
        const etcDir = this.resolveConfinedRootfsDir(safeName, 'etc', false);
        if (!etcDir)
            return dnsList;
        // 1. Replace broken/dangling symlink /etc/resolv.conf with real regular file
        try {
            const resolvPath = path_1.default.join(etcDir, 'resolv.conf');
            command_runner_1.privilegedFs.unlinkSync(resolvPath);
            const resolvBody = ['# Managed by TGVPANEL', ...dnsList.map((ns) => `nameserver ${ns}`), 'options timeout:2 attempts:2', ''].join('\n');
            command_runner_1.privilegedFs.writeFileSync(resolvPath, resolvBody, 0o644);
        }
        catch {
            // non-fatal on read-only rootfs
        }
        // 2. Configure systemd-resolved upstream drop-in AND normalize /etc/nsswitch.conf
        // (`hosts: files resolve [!UNAVAIL=return] dns` on Ubuntu 22.04/24.04 blocks glibc from
        // falling back to /etc/resolv.conf when systemd-resolved in memory has stale/empty state!)
        try {
            const nssPath = path_1.default.join(etcDir, 'nsswitch.conf');
            if (command_runner_1.privilegedFs.existsSync(nssPath) && !command_runner_1.privilegedFs.lstatMetaSync(nssPath).isSymbolicLink) {
                const nssRaw = command_runner_1.privilegedFs.readTextSync(nssPath);
                if (/^hosts:.*\[!UNAVAIL=return\]/m.test(nssRaw)) {
                    const nssFixed = nssRaw.replace(/^hosts:.*$/m, 'hosts:          files dns');
                    command_runner_1.privilegedFs.writeFileSync(nssPath, nssFixed, 0o644);
                }
            }
        }
        catch {
            // ignore
        }
        try {
            const systemdDir = this.resolveConfinedRootfsDir(safeName, 'etc/systemd', false);
            if (systemdDir) {
                const dropinDir = this.resolveConfinedRootfsDir(safeName, 'etc/systemd/resolved.conf.d', true);
                if (dropinDir) {
                    const dropinContent = `[Resolve]\nDNS=${dnsList.join(' ')}\nFallbackDNS=1.0.0.1 8.8.4.4\n`;
                    command_runner_1.privilegedFs.writeFileSync(path_1.default.join(dropinDir, '99-hkvm-dns.conf'), dropinContent, 0o644);
                }
            }
        }
        catch {
            // ignore
        }
        const ipv4Cidr = opts.ipv4Cidr ? opts.ipv4Cidr.trim() : null;
        const gateway = opts.gateway && opts.gateway !== 'auto' ? opts.gateway.trim() : null;
        // 3. Synchronize Ubuntu Netplan (/etc/netplan/10-lxc.yaml) so systemd-networkd does not flush eth0!
        try {
            const netplanDir = this.resolveConfinedRootfsDir(safeName, 'etc/netplan', false);
            if (netplanDir) {
                const netplanFile = path_1.default.join(netplanDir, '10-lxc.yaml');
                if (ipv4Cidr) {
                    const cidrFormatted = ipv4Cidr.includes('/') ? ipv4Cidr : `${ipv4Cidr}/24`;
                    const routeBlock = gateway
                        ? `      routes:\n        - to: default\n          via: ${gateway}\n`
                        : '';
                    const yaml = [
                        '# Managed by TGVPANEL',
                        'network:',
                        '  version: 2',
                        '  ethernets:',
                        '    eth0:',
                        '      dhcp4: false',
                        '      addresses:',
                        `        - ${cidrFormatted}`,
                        routeBlock ? routeBlock.trimEnd() : '',
                        '      nameservers:',
                        `        addresses: [${dnsList.join(', ')}]`,
                        '',
                    ]
                        .filter((l) => l !== '')
                        .join('\n') + '\n';
                    command_runner_1.privilegedFs.unlinkSync(netplanFile);
                    command_runner_1.privilegedFs.writeFileSync(netplanFile, yaml, 0o600);
                }
                else if (opts.useDhcp) {
                    const yaml = [
                        '# Managed by TGVPANEL',
                        'network:',
                        '  version: 2',
                        '  ethernets:',
                        '    eth0:',
                        '      dhcp4: true',
                        '      nameservers:',
                        `        addresses: [${dnsList.join(', ')}]`,
                        '',
                    ].join('\n');
                    if (command_runner_1.privilegedFs.existsSync(netplanFile)) {
                        const existingYaml = command_runner_1.privilegedFs.readTextSync(netplanFile);
                        if (existingYaml.includes('Managed by TGVPANEL') ||
                            existingYaml.includes('Managed by HKVM Panel')) {
                            command_runner_1.privilegedFs.writeFileSync(netplanFile, yaml, 0o600);
                        }
                    }
                }
            }
        }
        catch {
            // ignore
        }
        // 4. Synchronize systemd-networkd (/etc/systemd/network/05-hkvm-eth0.network) when netplan is absent
        try {
            const netplanDir = this.resolveConfinedRootfsDir(safeName, 'etc/netplan', false);
            const networkdDir = this.resolveConfinedRootfsDir(safeName, 'etc/systemd/network', false);
            if (!netplanDir && networkdDir) {
                const unitPath = path_1.default.join(networkdDir, '05-hkvm-eth0.network');
                if (ipv4Cidr) {
                    const cidrFormatted = ipv4Cidr.includes('/') ? ipv4Cidr : `${ipv4Cidr}/24`;
                    const lines = [
                        '# Managed by TGVPANEL',
                        '[Match]',
                        'Name=eth0',
                        '',
                        '[Network]',
                        'DHCP=no',
                        'KeepConfiguration=yes',
                        `Address=${cidrFormatted}`,
                    ];
                    if (gateway)
                        lines.push(`Gateway=${gateway}`);
                    for (const ns of dnsList)
                        lines.push(`DNS=${ns}`);
                    lines.push('');
                    command_runner_1.privilegedFs.unlinkSync(unitPath);
                    command_runner_1.privilegedFs.writeFileSync(unitPath, lines.join('\n'), 0o644);
                }
                else if (opts.useDhcp && command_runner_1.privilegedFs.existsSync(unitPath)) {
                    command_runner_1.privilegedFs.unlinkSync(unitPath);
                }
            }
        }
        catch {
            // ignore
        }
        // 5. Synchronize Debian / Alpine /etc/network/interfaces if present
        try {
            const netIfDir = this.resolveConfinedRootfsDir(safeName, 'etc/network', false);
            if (netIfDir && ipv4Cidr) {
                const ifacesPath = path_1.default.join(netIfDir, 'interfaces');
                if (command_runner_1.privilegedFs.existsSync(ifacesPath) && !command_runner_1.privilegedFs.lstatMetaSync(ifacesPath).isSymbolicLink) {
                    const curTxt = command_runner_1.privilegedFs.readTextSync(ifacesPath);
                    if (/iface\s+eth0\s+inet\s+dhcp/i.test(curTxt) || curTxt.includes('# HKVM-ETH0')) {
                        const [ipOnly, pfxRaw] = (ipv4Cidr.includes('/') ? ipv4Cidr : `${ipv4Cidr}/24`).split('/');
                        const mask = prefixLenToNetmask(parseInt(pfxRaw || '24', 10) || 24);
                        const staticStanza = [
                            '# HKVM-ETH0',
                            'auto eth0',
                            'iface eth0 inet static',
                            `    address ${ipOnly}`,
                            `    netmask ${mask}`,
                            ...(gateway ? [`    gateway ${gateway}`] : []),
                        ].join('\n');
                        const stripped = curTxt
                            .replace(/# HKVM-ETH0[\s\S]*?(?=\n(?:auto|allow-|iface|source)\b|$)/g, '')
                            .replace(/^\s*auto\s+eth0\s*$/gm, '')
                            .replace(/^\s*iface\s+eth0\s+inet\s+dhcp\s*$/gim, '');
                        command_runner_1.privilegedFs.writeFileSync(ifacesPath, `${stripped.trimEnd()}\n\n${staticStanza}\n`, 0o644);
                    }
                }
            }
        }
        catch {
            // ignore
        }
        return dnsList;
    }
    async listContainers() {
        if (!(0, command_runner_1.isBinaryAvailable)('lxc-ls')) {
            return [];
        }
        if (!command_runner_1.privilegedFs.existsSync(this.lxcBaseDir)) {
            return [];
        }
        const lsRes = await (0, command_runner_1.runAllowlistedCommand)('lxc-ls', [...this.lxcPathArgs(), '-1'], {
            timeoutMs: 10_000,
            asRoot: this.needsRootForStore() || undefined,
        });
        if (lsRes.exitCode !== 0)
            return [];
        const names = lsRes.stdout
            .split('\n')
            .map((s) => s.trim())
            .filter(Boolean);
        const results = [];
        for (const name of names) {
            try {
                results.push(await this.inspectContainer(name));
            }
            catch {
                // skip invalid entries
            }
        }
        return results;
    }
    readContainerNetFromConfig(containerName) {
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        const configPath = path_1.default.join(this.lxcBaseDir, safeName, 'config');
        if (!command_runner_1.privilegedFs.existsSync(configPath)) {
            return { bridge: null, ipv4Cidr: null, gateway: null };
        }
        try {
            const txt = command_runner_1.privilegedFs.readTextSync(configPath);
            const brMatches = [...txt.matchAll(/^\s*lxc\.net\.0\.link\s*=\s*(\S+)/gm)];
            const ipMatches = [...txt.matchAll(/^\s*lxc\.net\.0\.ipv4\.address\s*=\s*(\S+)/gm)];
            const gwMatches = [...txt.matchAll(/^\s*lxc\.net\.0\.ipv4\.gateway\s*=\s*(\S+)/gm)];
            return {
                bridge: brMatches.length > 0 ? brMatches[brMatches.length - 1][1].trim() : null,
                ipv4Cidr: ipMatches.length > 0 ? ipMatches[ipMatches.length - 1][1].trim() : null,
                gateway: gwMatches.length > 0 ? gwMatches[gwMatches.length - 1][1].trim() : null,
            };
        }
        catch {
            return { bridge: null, ipv4Cidr: null, gateway: null };
        }
    }
    async inspectContainer(containerName, options) {
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        const configPath = path_1.default.join(this.lxcBaseDir, safeName, 'config');
        const cfgNet = this.readContainerNetFromConfig(safeName);
        const configuredIpv4 = cfgNet.ipv4Cidr ? cfgNet.ipv4Cidr.split('/')[0] : null;
        const configuredGateway = cfgNet.gateway || null;
        if (!(0, command_runner_1.isBinaryAvailable)('lxc-info')) {
            const existsOnDisk = command_runner_1.privilegedFs.existsSync(configPath);
            this.prevCpuSamples.delete(safeName);
            return {
                name: safeName,
                state: existsOnDisk ? 'stopped' : 'missing',
                pid: null,
                ips: configuredIpv4 ? [configuredIpv4] : [],
                cpuUseSeconds: 0,
                cpuCoresUsed: 0,
                memoryBytes: 0,
                swapBytes: 0,
                rxBytes: 0,
                txBytes: 0,
                diskUsedBytes: this.measureDirBytesFast(path_1.default.join(this.lxcBaseDir, safeName, 'rootfs')),
                configuredIpv4,
                configuredGateway,
            };
        }
        const res = await (0, command_runner_1.runAllowlistedCommand)('lxc-info', [...this.lxcPathArgs(), '-n', safeName], {
            timeoutMs: 10_000,
            asRoot: this.needsRootForStore() || undefined,
        });
        if (res.exitCode !== 0) {
            const existsOnDisk = command_runner_1.privilegedFs.existsSync(configPath);
            this.prevCpuSamples.delete(safeName);
            return {
                name: safeName,
                state: existsOnDisk ? 'stopped' : 'missing',
                pid: null,
                ips: [],
                cpuUseSeconds: 0,
                cpuCoresUsed: 0,
                memoryBytes: 0,
                swapBytes: 0,
                rxBytes: 0,
                txBytes: 0,
                diskUsedBytes: 0,
                configuredIpv4,
                configuredGateway,
            };
        }
        let state = 'stopped';
        let pid = null;
        const ips = [];
        let lxcInfoCpuSeconds = 0;
        let memoryBytes = 0;
        let swapBytes = 0;
        let rxBytes = 0;
        let txBytes = 0;
        for (const line of res.stdout.split('\n')) {
            const [rawKey, ...rest] = line.split(':');
            if (!rawKey || rest.length === 0)
                continue;
            const key = rawKey.trim().toLowerCase();
            const val = rest.join(':').trim();
            if (key === 'state') {
                const s = val.toLowerCase();
                if (s.includes('running'))
                    state = 'running';
                else if (s.includes('frozen'))
                    state = 'frozen';
                else
                    state = 'stopped';
            }
            else if (key === 'pid') {
                const n = parseInt(val, 10);
                if (!Number.isNaN(n) && n > 0)
                    pid = n;
            }
            else if (key === 'ip') {
                ips.push(val);
            }
            else if (key === 'cpu use') {
                lxcInfoCpuSeconds = parseFloat(val.replace(/[^0-9.]/g, '')) || 0;
            }
            else if (key === 'memory use') {
                memoryBytes = this.parseHumanSizeToBytes(val);
            }
            else if (key === 'rx bytes') {
                rxBytes += this.parseHumanSizeToBytes(val);
            }
            else if (key === 'tx bytes') {
                txBytes += this.parseHumanSizeToBytes(val);
            }
        }
        const diskUsedBytes = await this.getRootfsUsedBytes(safeName);
        const hasLoopDisk = command_runner_1.privilegedFs.existsSync(this.getQuotaDiskImagePath(safeName)) ||
            Boolean((0, command_runner_1.findActiveMountSource)(this.getRootfsDir(safeName)));
        let cpuUseSeconds = lxcInfoCpuSeconds;
        let cpuCoresUsed = 0;
        if (state === 'running' || state === 'frozen') {
            const sample1 = this.readHighResContainerTelemetrySample(safeName, pid, lxcInfoCpuSeconds, memoryBytes === 0);
            cpuUseSeconds = sample1.cpuUseSeconds;
            if (memoryBytes === 0 && sample1.memoryBytes > 0) {
                memoryBytes = sample1.memoryBytes;
            }
            if (sample1.swapBytes > 0) {
                swapBytes = sample1.swapBytes;
            }
            if (state === 'running') {
                cpuCoresUsed = await this.computeContainerCpuCoresUsed(safeName, pid, sample1.source, sample1.cpuUseSeconds, sample1.monoMs, Boolean(options?.sampleCpu), () => {
                    const next = this.readHighResContainerTelemetrySample(safeName, pid, lxcInfoCpuSeconds, false);
                    cpuUseSeconds = next.cpuUseSeconds;
                    return next;
                });
            }
        }
        else {
            this.prevCpuSamples.delete(safeName);
        }
        return {
            name: safeName,
            state,
            pid,
            ips,
            cpuUseSeconds,
            cpuCoresUsed,
            memoryBytes,
            swapBytes,
            rxBytes,
            txBytes,
            diskUsedBytes,
            backingStore: hasLoopDisk ? 'loop' : 'dir',
            diskQuotaEnforced: hasLoopDisk,
            configuredIpv4,
            configuredGateway,
        };
    }
    readHighResContainerTelemetrySample(safeName, pid, lxcInfoCpuSeconds, needMemoryFallback) {
        const cgStats = readContainerCgroupResourceStats(safeName, pid);
        const monoAfterCg = Number(process.hrtime.bigint()) / 1e6;
        let cpuUseSeconds = lxcInfoCpuSeconds;
        let source = 'lxc-info';
        let memoryBytes = cgStats.memoryBytes ?? 0;
        const swapBytes = cgStats.swapBytes ?? 0;
        if (cgStats.cpuUseSeconds !== null && cgStats.source) {
            cpuUseSeconds = cgStats.cpuUseSeconds;
            source = cgStats.source;
        }
        const needProcCpu = cgStats.cpuUseSeconds === null && pid !== null && pid > 0;
        const needProcMem = needMemoryFallback && memoryBytes === 0 && pid !== null && pid > 0;
        if (needProcCpu || needProcMem) {
            const procStats = this.measureContainerProcTree(pid);
            const monoAfterProc = Number(process.hrtime.bigint()) / 1e6;
            if (needProcMem && procStats.memoryBytes > 0) {
                memoryBytes = procStats.memoryBytes;
            }
            if (needProcCpu && (procStats.cpuUseSeconds > 0 || lxcInfoCpuSeconds === 0)) {
                cpuUseSeconds = procStats.cpuUseSeconds;
                source = 'proc';
                return {
                    cpuUseSeconds,
                    memoryBytes,
                    swapBytes,
                    source,
                    monoMs: monoAfterProc,
                };
            }
        }
        return {
            cpuUseSeconds,
            memoryBytes,
            swapBytes,
            source,
            monoMs: monoAfterCg,
        };
    }
    /**
     * Computes real-time active CPU cores utilized (`deltaCpuSec / deltaWallSec`) using the
     * host's monotonic clock. Performs a fast 120ms kernel cgroup/`/proc` micro-sample on
     * cold starts when `sampleIfCold` is enabled so opening an LXC VPS page immediately
     * displays live CPU Load instead of `0%`.
     */
    async computeContainerCpuCoresUsed(safeName, pid, source, cpuSec1, monoMs1, sampleIfCold, readSecondSample) {
        const prev = this.prevCpuSamples.get(safeName);
        if (prev &&
            prev.pid === pid &&
            prev.source === source &&
            cpuSec1 >= prev.cpuSec &&
            monoMs1 >= prev.monoMs) {
            const elapsedMs = monoMs1 - prev.monoMs;
            if (elapsedMs < 200) {
                return prev.cpuCoresUsed;
            }
            if (elapsedMs <= 30_000) {
                const cpuCoresUsed = Math.max(0, (cpuSec1 - prev.cpuSec) / (elapsedMs / 1000));
                this.prevCpuSamples.set(safeName, {
                    pid,
                    source,
                    cpuSec: cpuSec1,
                    monoMs: monoMs1,
                    cpuCoresUsed,
                });
                return cpuCoresUsed;
            }
        }
        if (sampleIfCold &&
            readSecondSample &&
            (source === 'cgroup-v2' || source === 'cgroup-v1' || source === 'proc')) {
            await new Promise((r) => setTimeout(r, 120));
            const sample2 = readSecondSample();
            const elapsedMs = sample2.monoMs - monoMs1;
            if (sample2.source === source &&
                elapsedMs > 20 &&
                sample2.cpuUseSeconds >= cpuSec1) {
                const cpuCoresUsed = Math.max(0, (sample2.cpuUseSeconds - cpuSec1) / (elapsedMs / 1000));
                this.prevCpuSamples.set(safeName, {
                    pid,
                    source: sample2.source,
                    cpuSec: sample2.cpuUseSeconds,
                    monoMs: sample2.monoMs,
                    cpuCoresUsed,
                });
                return cpuCoresUsed;
            }
        }
        this.prevCpuSamples.set(safeName, {
            pid,
            source,
            cpuSec: cpuSec1,
            monoMs: monoMs1,
            cpuCoresUsed: 0,
        });
        return 0;
    }
    /**
     * Fallback live memory (VmRSS) & monotonic CPU time aggregator across `<initPid>` and all
     * its descendant processes in `/proc` for hosts (e.g. WSL2 / un-delegated cgroup v2) where
     * per-container cgroup accounting is unavailable. Includes `cutime + cstime` so reaped
     * short-lived child processes never make cumulative CPU ticks drop backwards.
     */
    measureContainerProcTree(rootPid) {
        try {
            if (!fs_1.default.existsSync('/proc'))
                return { memoryBytes: 0, cpuUseSeconds: 0 };
            const entries = fs_1.default.readdirSync('/proc');
            const childrenByPpid = new Map();
            const ticksByPid = new Map();
            for (const ent of entries) {
                if (!/^\d+$/.test(ent))
                    continue;
                const p = parseInt(ent, 10);
                try {
                    const statRaw = fs_1.default.readFileSync(`/proc/${p}/stat`, 'utf8');
                    const closeParen = statRaw.lastIndexOf(')');
                    if (closeParen === -1)
                        continue;
                    const rest = statRaw.slice(closeParen + 2).trim().split(/\s+/);
                    const ppid = parseInt(rest[1] || '0', 10);
                    const utime = parseInt(rest[11] || '0', 10) || 0;
                    const stime = parseInt(rest[12] || '0', 10) || 0;
                    const cutime = parseInt(rest[13] || '0', 10) || 0;
                    const cstime = parseInt(rest[14] || '0', 10) || 0;
                    ticksByPid.set(p, utime + stime + cutime + cstime);
                    if (ppid > 0) {
                        const arr = childrenByPpid.get(ppid) || [];
                        arr.push(p);
                        childrenByPpid.set(ppid, arr);
                    }
                }
                catch {
                    // process exited between readdir and readFile
                }
            }
            const treePids = [];
            const visited = new Set();
            const queue = [rootPid];
            while (queue.length > 0) {
                const cur = queue.shift();
                if (visited.has(cur))
                    continue;
                visited.add(cur);
                treePids.push(cur);
                const kids = childrenByPpid.get(cur);
                if (kids) {
                    for (const k of kids) {
                        if (!visited.has(k))
                            queue.push(k);
                    }
                }
            }
            let totalRssBytes = 0;
            let totalTicks = 0;
            for (const tp of treePids) {
                totalTicks += ticksByPid.get(tp) || 0;
                try {
                    const statusTxt = fs_1.default.readFileSync(`/proc/${tp}/status`, 'utf8');
                    const m = statusTxt.match(/^VmRSS:\s*(\d+)\s*kB/m);
                    if (m) {
                        totalRssBytes += (parseInt(m[1], 10) || 0) * 1024;
                    }
                }
                catch {
                    // ignore exited child
                }
            }
            return {
                memoryBytes: totalRssBytes,
                cpuUseSeconds: totalTicks / 100,
            };
        }
        catch {
            return { memoryBytes: 0, cpuUseSeconds: 0 };
        }
    }
    parseHumanSizeToBytes(text) {
        const m = text.trim().match(/^([0-9.]+)\s*([KMGTPE]?i?B?)/i);
        if (!m)
            return 0;
        const num = parseFloat(m[1]) || 0;
        const unit = (m[2] || '').toUpperCase();
        if (unit.startsWith('K'))
            return Math.round(num * 1024);
        if (unit.startsWith('M'))
            return Math.round(num * 1024 * 1024);
        if (unit.startsWith('G'))
            return Math.round(num * 1024 * 1024 * 1024);
        if (unit.startsWith('T'))
            return Math.round(num * 1024 * 1024 * 1024 * 1024);
        return Math.round(num);
    }
    measureDirBytesFast(dirPath) {
        try {
            return command_runner_1.privilegedFs.lstatMetaSync(dirPath).size;
        }
        catch {
            return 0;
        }
    }
    async getRootfsUsedBytes(containerName) {
        const rootfs = this.getRootfsDir(containerName);
        if (!command_runner_1.privilegedFs.existsSync(rootfs))
            return 0;
        // Fast kernel statfs path when rootfs is a dedicated loop-mounted ext4 quota volume
        if ((0, command_runner_1.findActiveMountSource)(rootfs) && (0, command_runner_1.isBinaryAvailable)('df')) {
            const dfRes = await (0, command_runner_1.runAllowlistedCommand)('df', ['-B1', '--output=used', rootfs], {
                timeoutMs: 4000,
                asRoot: true,
            });
            if (dfRes.exitCode === 0) {
                const lines = dfRes.stdout.trim().split('\n');
                const val = parseInt((lines[lines.length - 1] || '').trim(), 10);
                if (!Number.isNaN(val) && val >= 0)
                    return val;
            }
        }
        if ((0, command_runner_1.isBinaryAvailable)('du')) {
            const res = await (0, command_runner_1.runAllowlistedCommand)('du', ['-sb', rootfs], {
                timeoutMs: 8000,
                asRoot: true,
            });
            if (res.exitCode === 0) {
                const bytes = parseInt(res.stdout.trim().split(/\s+/)[0] || '0', 10);
                if (!Number.isNaN(bytes))
                    return bytes;
            }
        }
        return 0;
    }
    getQuotaDiskDir() {
        if (this.isSystemLxcStore()) {
            return '/var/lib/hkvm-lxc-disks';
        }
        return path_1.default.join(path_1.default.dirname(path_1.default.resolve(this.lxcBaseDir)), 'hkvm-lxc-disks');
    }
    getQuotaDiskImagePath(containerName) {
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        return path_1.default.join(this.getQuotaDiskDir(), `${safeName}.ext4`);
    }
    /**
     * Ensures an existing sparse `.ext4` quota volume is loop-mounted onto `<ctDir>/rootfs`
     * (for example after a host reboot before `lxc-start`).
     */
    async ensureExistingQuotaDiskMounted(containerName) {
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        const imgPath = this.getQuotaDiskImagePath(safeName);
        if (!command_runner_1.privilegedFs.existsSync(imgPath))
            return false;
        const rootfsDir = this.getRootfsDir(safeName);
        command_runner_1.privilegedFs.mkdirpSync(rootfsDir, 0o755);
        if ((0, command_runner_1.findActiveMountSource)(rootfsDir))
            return true;
        if (!(0, command_runner_1.isBinaryAvailable)('mount') || (!(0, command_runner_1.isRunningAsRoot)() && !(0, command_runner_1.canPasswordlessSudo)())) {
            return false;
        }
        let mntRes = await (0, command_runner_1.runAllowlistedCommand)('mount', ['-o', 'loop', imgPath, rootfsDir], {
            timeoutMs: 15_000,
            asRoot: true,
        });
        if (mntRes.exitCode !== 0 && (0, command_runner_1.isBinaryAvailable)('e2fsck')) {
            await (0, command_runner_1.runAllowlistedCommand)('e2fsck', ['-fy', imgPath], {
                timeoutMs: 60_000,
                asRoot: true,
            }).catch(() => undefined);
            mntRes = await (0, command_runner_1.runAllowlistedCommand)('mount', ['-o', 'loop', imgPath, rootfsDir], {
                timeoutMs: 15_000,
                asRoot: true,
            });
        }
        return mntRes.exitCode === 0 && Boolean((0, command_runner_1.findActiveMountSource)(rootfsDir));
    }
    /**
     * Unmounts `<ctDir>/rootfs` if backed by a loop mount, and optionally deletes the `.ext4` image.
     */
    async unmountQuotaDiskIfMounted(containerName, removeImage = false) {
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        const rootfsDir = this.getRootfsDir(safeName);
        if ((0, command_runner_1.findActiveMountSource)(rootfsDir) && (0, command_runner_1.isBinaryAvailable)('umount')) {
            const uRes = await (0, command_runner_1.runAllowlistedCommand)('umount', [rootfsDir], {
                timeoutMs: 10_000,
                asRoot: true,
            });
            if (uRes.exitCode !== 0) {
                await (0, command_runner_1.runAllowlistedCommand)('umount', ['-l', rootfsDir], {
                    timeoutMs: 10_000,
                    asRoot: true,
                }).catch(() => undefined);
            }
        }
        if (removeImage) {
            const imgPath = this.getQuotaDiskImagePath(safeName);
            if (command_runner_1.privilegedFs.existsSync(imgPath)) {
                command_runner_1.privilegedFs.unlinkSync(imgPath);
            }
        }
    }
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
    async ensureContainerQuotaDisk(containerName, diskGb, options = {}) {
        if (!options.allowNonSystemStore &&
            !this.isSystemLxcStore() &&
            process.env.HKVM_FORCE_LOOP_QUOTA !== 'true') {
            return false;
        }
        const requiredBins = ['truncate', 'mkfs.ext4', 'mount', 'umount', 'losetup', 'resize2fs'];
        if (requiredBins.some((b) => !(0, command_runner_1.isBinaryAvailable)(b))) {
            return false;
        }
        if (!(0, command_runner_1.isRunningAsRoot)() && !(0, command_runner_1.canPasswordlessSudo)()) {
            return false;
        }
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        const rootfsDir = this.getRootfsDir(safeName);
        if (!command_runner_1.privilegedFs.existsSync(rootfsDir))
            return false;
        const diskDir = this.getQuotaDiskDir();
        command_runner_1.privilegedFs.mkdirpSync(diskDir, 0o700);
        const imgPath = this.getQuotaDiskImagePath(safeName);
        const targetBytes = Math.max(1, Math.round(Number(diskGb || 20))) * 1024 * 1024 * 1024;
        // 1. Existing `.ext4` quota volume: ensure mounted & grow online/offline if diskGb increased
        if (command_runner_1.privilegedFs.existsSync(imgPath)) {
            const mountedOk = await this.ensureExistingQuotaDiskMounted(safeName);
            if (!mountedOk)
                return false;
            const meta = command_runner_1.privilegedFs.lstatMetaSync(imgPath);
            if (targetBytes > meta.size + 64 * 1024 * 1024) {
                const truncRes = await (0, command_runner_1.runAllowlistedCommand)('truncate', ['-s', String(targetBytes), imgPath], { timeoutMs: 15_000, asRoot: true });
                if (truncRes.exitCode === 0) {
                    const loopSrc = (0, command_runner_1.findActiveMountSource)(rootfsDir);
                    if (loopSrc && loopSrc.startsWith('/dev/loop')) {
                        await (0, command_runner_1.runAllowlistedCommand)('losetup', ['-c', loopSrc], {
                            timeoutMs: 10_000,
                            asRoot: true,
                        });
                        await (0, command_runner_1.runAllowlistedCommand)('resize2fs', [loopSrc], {
                            timeoutMs: 60_000,
                            asRoot: true,
                        });
                    }
                    else {
                        if ((0, command_runner_1.isBinaryAvailable)('e2fsck')) {
                            await (0, command_runner_1.runAllowlistedCommand)('e2fsck', ['-fy', imgPath], {
                                timeoutMs: 60_000,
                                asRoot: true,
                            }).catch(() => undefined);
                        }
                        await (0, command_runner_1.runAllowlistedCommand)('resize2fs', [imgPath], {
                            timeoutMs: 60_000,
                            asRoot: true,
                        });
                    }
                }
            }
            return true;
        }
        // 2. Convert plain `dir` rootfs into a sparse loop-mounted `ext4` quota volume (container must be stopped)
        const curState = await this.inspectContainer(safeName);
        if (curState.state === 'running' || curState.state === 'frozen') {
            return false;
        }
        if ((0, command_runner_1.findActiveMountSource)(rootfsDir)) {
            return true;
        }
        const usedBytes = await this.getRootfsUsedBytes(safeName);
        const effectiveBytes = Math.max(targetBytes, usedBytes + 512 * 1024 * 1024);
        const tmpImgPath = `${imgPath}.tmp`;
        const probeDir = path_1.default.join(this.getContainerDir(safeName), '.rootfs-loop-probe');
        if (command_runner_1.privilegedFs.existsSync(tmpImgPath))
            command_runner_1.privilegedFs.unlinkSync(tmpImgPath);
        if (command_runner_1.privilegedFs.existsSync(probeDir))
            command_runner_1.privilegedFs.rmRecursiveSync(probeDir);
        const truncRes = await (0, command_runner_1.runAllowlistedCommand)('truncate', ['-s', String(effectiveBytes), tmpImgPath], { timeoutMs: 15_000, asRoot: true });
        if (truncRes.exitCode !== 0) {
            if (command_runner_1.privilegedFs.existsSync(tmpImgPath))
                command_runner_1.privilegedFs.unlinkSync(tmpImgPath);
            return false;
        }
        const mkfsRes = await (0, command_runner_1.runAllowlistedCommand)('mkfs.ext4', [
            '-q',
            '-F',
            '-m',
            '0',
            '-d',
            rootfsDir,
            '-E',
            'lazy_itable_init=1,lazy_journal_init=1',
            tmpImgPath,
        ], { timeoutMs: 300_000, asRoot: true });
        if (mkfsRes.exitCode !== 0) {
            if (command_runner_1.privilegedFs.existsSync(tmpImgPath))
                command_runner_1.privilegedFs.unlinkSync(tmpImgPath);
            return false;
        }
        // Probe-mount BEFORE touching `rootfsDir` so restricted kernels never affect guest files
        command_runner_1.privilegedFs.mkdirpSync(probeDir, 0o700);
        const probeMnt = await (0, command_runner_1.runAllowlistedCommand)('mount', ['-o', 'loop', tmpImgPath, probeDir], {
            timeoutMs: 15_000,
            asRoot: true,
        });
        if (probeMnt.exitCode !== 0) {
            command_runner_1.privilegedFs.rmRecursiveSync(probeDir);
            command_runner_1.privilegedFs.unlinkSync(tmpImgPath);
            return false;
        }
        await (0, command_runner_1.runAllowlistedCommand)('umount', [probeDir], {
            timeoutMs: 10_000,
            asRoot: true,
        }).catch(() => (0, command_runner_1.runAllowlistedCommand)('umount', ['-l', probeDir], { timeoutMs: 10_000, asRoot: true }));
        command_runner_1.privilegedFs.rmRecursiveSync(probeDir);
        // Atomic directory swap -> mount `.ext4` onto `rootfsDir`
        const bakDir = `${rootfsDir}.preloop-bak`;
        if (command_runner_1.privilegedFs.existsSync(bakDir))
            command_runner_1.privilegedFs.rmRecursiveSync(bakDir);
        command_runner_1.privilegedFs.renameSync(rootfsDir, bakDir);
        command_runner_1.privilegedFs.mkdirpSync(rootfsDir, 0o755);
        command_runner_1.privilegedFs.renameSync(tmpImgPath, imgPath);
        const finalMnt = await (0, command_runner_1.runAllowlistedCommand)('mount', ['-o', 'loop', imgPath, rootfsDir], {
            timeoutMs: 15_000,
            asRoot: true,
        });
        if (finalMnt.exitCode === 0 && (0, command_runner_1.findActiveMountSource)(rootfsDir)) {
            command_runner_1.privilegedFs.rmRecursiveSync(bakDir);
            return true;
        }
        // Rollback on unexpected mount failure
        await (0, command_runner_1.runAllowlistedCommand)('umount', ['-l', rootfsDir], {
            timeoutMs: 10_000,
            asRoot: true,
        }).catch(() => undefined);
        command_runner_1.privilegedFs.rmRecursiveSync(rootfsDir);
        command_runner_1.privilegedFs.renameSync(bakDir, rootfsDir);
        if (command_runner_1.privilegedFs.existsSync(imgPath))
            command_runner_1.privilegedFs.unlinkSync(imgPath);
        return false;
    }
    async createFromLocalArchive(safeName, archivePath) {
        const resolvedArchive = path_1.default.resolve(archivePath);
        if (!fs_1.default.existsSync(resolvedArchive)) {
            throw new Error(`Custom LXC template archive not found at ${resolvedArchive}`);
        }
        const ctDir = this.getContainerDir(safeName);
        const rootfsDir = this.getRootfsDir(safeName);
        command_runner_1.privilegedFs.mkdirpSync(rootfsDir, 0o755);
        const tarRes = await (0, command_runner_1.runAllowlistedCommand)('tar', ['--numeric-owner', '-xpf', resolvedArchive, '-C', rootfsDir], {
            timeoutMs: 600_000,
            asRoot: true,
        });
        if (tarRes.exitCode !== 0) {
            command_runner_1.privilegedFs.rmRecursiveSync(ctDir);
            throw new Error(`Failed to unpack custom LXC rootfs archive: ${tarRes.stderr || tarRes.stdout}`);
        }
        const baseConfigLines = [
            '# Distribution configuration',
            ...(fs_1.default.existsSync('/usr/share/lxc/config/common.conf')
                ? ['lxc.include = /usr/share/lxc/config/common.conf']
                : []),
            `lxc.arch = ${process.arch === 'arm64' ? 'aarch64' : 'x86_64'}`,
            '',
            '# Container specific configuration',
            `lxc.rootfs.path = dir:${rootfsDir}`,
            `lxc.uts.name = ${safeName}`,
            '',
        ];
        command_runner_1.privilegedFs.writeFileSync(path_1.default.join(ctDir, 'config'), baseConfigLines.join('\n'), 0o640);
    }
    async applyOfflineRootPasswordHash(safeName, plainPassword) {
        if (!plainPassword || plainPassword.includes('\n') || plainPassword.includes('\0')) {
            return false;
        }
        if (!(0, command_runner_1.isBinaryAvailable)('openssl'))
            return false;
        const shadowPath = path_1.default.join(this.getRootfsDir(safeName), 'etc', 'shadow');
        if (!command_runner_1.privilegedFs.existsSync(shadowPath))
            return false;
        const hashRes = await (0, command_runner_1.runAllowlistedCommand)('openssl', ['passwd', '-6', '-stdin'], {
            stdinData: `${plainPassword}\n`,
            timeoutMs: 5000,
            asRoot: false,
        });
        const passwordHash = hashRes.stdout.trim();
        if (hashRes.exitCode !== 0 || !passwordHash.startsWith('$6$')) {
            return false;
        }
        try {
            const shadowContent = command_runner_1.privilegedFs.readTextSync(shadowPath);
            const lines = shadowContent.split('\n');
            let replaced = false;
            const updated = lines.map((line) => {
                if (line.startsWith('root:')) {
                    const parts = line.split(':');
                    parts[1] = passwordHash;
                    replaced = true;
                    return parts.join(':');
                }
                return line;
            });
            if (!replaced)
                return false;
            command_runner_1.privilegedFs.writeFileSync(shadowPath, updated.join('\n'), 0o640);
            return true;
        }
        catch {
            return false;
        }
    }
    async createContainer(spec) {
        this.assertLxcInstalled();
        const safeName = middleware_1.SafeValidators.containerName(spec.containerName);
        const lockKey = safeName.toLowerCase();
        if (this.inFlightCreations.has(lockKey)) {
            throw new Error(`LXC container "${safeName}" is currently being provisioned (downloading OS template). Please wait for it to finish.`);
        }
        this.inFlightCreations.add(lockKey);
        try {
            const requestedBacking = spec.backingStore === 'loop' ? 'dir' : (spec.backingStore || 'dir');
            const backing = requestedBacking;
            this.ensureHostLxcDirectories();
            // Clean up any leftover empty/corrupt/orphan directory if not registered in panel DB
            const existingInfo = await this.inspectContainer(safeName);
            const ctDir = this.getContainerDir(safeName);
            if (existingInfo.state !== 'missing') {
                if (spec.replaceOrphanOnHost) {
                    await this.destroyContainer(safeName).catch(() => undefined);
                    if (command_runner_1.privilegedFs.existsSync(ctDir)) {
                        command_runner_1.privilegedFs.rmRecursiveSync(ctDir);
                    }
                }
                else {
                    throw new Error(`LXC container "${safeName}" already exists on host (${existingInfo.state}).`);
                }
            }
            else if (command_runner_1.privilegedFs.existsSync(ctDir)) {
                command_runner_1.privilegedFs.rmRecursiveSync(ctDir);
            }
            if (spec.templateArchivePath && fs_1.default.existsSync(path_1.default.resolve(spec.templateArchivePath))) {
                await this.createFromLocalArchive(safeName, spec.templateArchivePath);
            }
            else {
                const { distro, releases, archMapper } = resolveDownloadReleaseCandidates(spec.distro, spec.release, spec.fallbackRelease);
                const arch = archMapper(spec.arch || 'amd64');
                const downloadEnv = {
                    DOWNLOAD_KEYSERVER: process.env.LXC_DOWNLOAD_KEYSERVER || 'hkp://keyserver.ubuntu.com:80',
                };
                let created = false;
                let lastFailure = '';
                for (const relCandidate of releases) {
                    const baseArgs = [
                        ...this.lxcPathArgs(),
                        '-n',
                        safeName,
                        '-B',
                        backing,
                        '-t',
                        'download',
                        '--',
                        '-d',
                        distro,
                        '-r',
                        relCandidate,
                        '-a',
                        arch,
                    ];
                    let createRes = await (0, command_runner_1.runAllowlistedCommand)('lxc-create', baseArgs, {
                        timeoutMs: 600_000,
                        env: downloadEnv,
                        asRoot: this.needsRootForStore() || undefined,
                    });
                    const combinedOut = `${createRes.stderr}\n${createRes.stdout}`;
                    if (createRes.exitCode !== 0 &&
                        process.env.HKVM_LXC_STRICT_GPG !== 'true' &&
                        /unable to fetch gpg key|gpg.*keyserver|gnupg/i.test(combinedOut)) {
                        if (command_runner_1.privilegedFs.existsSync(ctDir)) {
                            command_runner_1.privilegedFs.rmRecursiveSync(ctDir);
                        }
                        createRes = await (0, command_runner_1.runAllowlistedCommand)('lxc-create', [...baseArgs, '--no-validate'], {
                            timeoutMs: 600_000,
                            env: downloadEnv,
                            asRoot: this.needsRootForStore() || undefined,
                        });
                    }
                    if (createRes.exitCode === 0) {
                        created = true;
                        break;
                    }
                    lastFailure = `lxc-create failed (${createRes.exitCode}): ${(createRes.stderr || createRes.stdout).trim()}`;
                    if (command_runner_1.privilegedFs.existsSync(ctDir)) {
                        command_runner_1.privilegedFs.rmRecursiveSync(ctDir);
                    }
                    const retryNextRelease = /couldn't find a matching image|no matching image/i.test(`${createRes.stderr}\n${createRes.stdout}`);
                    if (!retryNextRelease) {
                        break;
                    }
                }
                if (!created) {
                    throw new Error(lastFailure || `lxc-create failed for ${distro}:${spec.release} (${arch})`);
                }
            }
            try {
                await this.writeManagedConfigSection(safeName, {
                    hostname: spec.hostname || safeName,
                    cpuCores: spec.cpuCores,
                    cpuShares: spec.cpuShares ?? 1024,
                    cpuLimitPercent: spec.cpuLimitPercent ?? 100,
                    cpuPinning: spec.cpuPinning || null,
                    ramMb: spec.ramMb,
                    swapMb: spec.swapMb ?? 512,
                    nesting: spec.nesting !== false,
                    kvmNesting: Boolean(spec.kvmNesting),
                    privileged: spec.privileged !== false,
                    apparmorProfile: spec.apparmorProfile || 'generated',
                    autostart: Boolean(spec.autostart),
                    bridge: spec.bridge || 'lxcbr0',
                    ipv4Address: spec.ipv4Address || null,
                    ipv4Gateway: spec.ipv4Gateway || null,
                    ipv6Address: spec.ipv6Address || null,
                    macAddress: spec.macAddress || null,
                    mounts: spec.mounts || [],
                });
                if (spec.rootPassword) {
                    await this.applyOfflineRootPasswordHash(safeName, spec.rootPassword);
                }
                if (spec.sshPublicKeys && spec.sshPublicKeys.length > 0) {
                    for (const pubKey of spec.sshPublicKeys) {
                        await this.injectSshPublicKey(safeName, pubKey);
                    }
                }
                // Convert plain `dir` rootfs into a dedicated sparse `ext4` loop quota volume so
                // `df -h` inside the container reports exact `spec.diskGb` (e.g. 20G) instead of host disk
                if ((!spec.backingStore || spec.backingStore === 'dir' || spec.backingStore === 'loop') && spec.diskGb >= 1) {
                    await this.ensureContainerQuotaDisk(safeName, spec.diskGb).catch(() => false);
                }
            }
            catch (cfgErr) {
                await this.destroyContainer(safeName).catch(() => {
                    if (command_runner_1.privilegedFs.existsSync(ctDir))
                        command_runner_1.privilegedFs.rmRecursiveSync(ctDir);
                });
                throw cfgErr;
            }
            let startupWarning;
            try {
                await this.startContainer(safeName);
                if (spec.rootPassword) {
                    await this.setRootPassword(safeName, spec.rootPassword).catch(() => undefined);
                }
            }
            catch (startErr) {
                const msg = String(startErr?.message || startErr);
                // Never discard a validly provisioned container if only initial auto-start failed:
                // keep it registered in 'stopped' state so the admin can inspect logs/config and start it.
                startupWarning = `Container rootfs and configuration were created on disk (status: stopped), but automatic startup encountered a host issue: ${msg}`;
            }
            const info = await this.inspectContainer(safeName);
            if (startupWarning) {
                info.startupWarning = startupWarning;
            }
            return info;
        }
        finally {
            this.inFlightCreations.delete(lockKey);
        }
    }
    async writeManagedConfigSection(containerName, cfg) {
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        const configFile = path_1.default.join(this.getContainerDir(safeName), 'config');
        if (!command_runner_1.privilegedFs.existsSync(configFile)) {
            throw new Error(`Container config not found at ${configFile}`);
        }
        const existing = command_runner_1.privilegedFs.readTextSync(configFile);
        const prevLimits = this.parseManagedLimitsComment(existing);
        const markerStart = '# --- BEGIN HKVM MANAGED CONFIG ---';
        const markerEnd = '# --- END HKVM MANAGED CONFIG ---';
        let stripped = existing.replace(new RegExp(`${markerStart}[\\s\\S]*?${markerEnd}\\n?`, 'g'), '');
        // Strip template-copied default lxc.net.0.*, lxc.apparmor.*, and stale cgroup placement directives
        if (cfg.bridge !== undefined) {
            stripped = stripped.replace(/^\s*lxc\.net\.0(?:\.[a-zA-Z0-9_.-]+)?\s*=.*$/gm, '');
        }
        stripped = stripped.replace(/^\s*lxc\.apparmor\.(?:profile|allow_nesting)\s*=.*$/gm, '');
        stripped = stripped.replace(/^\s*lxc\.cgroup\.(?:relative|dir(?:\.[a-zA-Z0-9_.-]+)?)\s*=.*$/gm, '');
        stripped = stripped.replace(/\n{3,}/g, '\n\n');
        const isSystemStore = this.isSystemLxcStore();
        // Delegate cgroup v2 controllers (`init.scope` + `hkvm.lxc`) FIRST, BEFORE spawning/probing `lxcfs`!
        const cgroupV2Controllers = readActiveCgroupV2Controllers(isSystemStore);
        if (isSystemStore) {
            await (0, command_runner_1.ensureLxcfsDaemonMounted)().catch(() => false);
        }
        const isCgroupV2 = cgroupV2Controllers !== null;
        const apparmorAvailable = isAppArmorProfileLoadable();
        const effectiveCores = Math.max(1, Number(cfg.cpuCores ?? prevLimits?.cpuCores ?? 1));
        const effectivePct = Math.min(100, Math.max(5, Number(cfg.cpuLimitPercent ?? prevLimits?.cpuLimitPercent ?? 100)));
        const effectiveRamMb = cfg.ramMb !== undefined ? Math.max(64, Number(cfg.ramMb)) : prevLimits?.ramMb;
        const effectiveSwapMb = cfg.swapMb !== undefined ? Math.max(0, Number(cfg.swapMb)) : prevLimits?.swapMb;
        const effectivePinning = cfg.cpuPinning !== undefined ? cfg.cpuPinning : (prevLimits?.cpuPinning ?? null);
        const quotaUs = Math.round(effectiveCores * 100_000 * (effectivePct / 100));
        const effectiveCpuset = selectContainerCpuset(safeName, effectiveCores, readEffectiveHostCpuIds(), effectivePinning);
        const lines = [
            markerStart,
            `# hkvm.limits: ram_mb=${effectiveRamMb ?? ''} swap_mb=${effectiveSwapMb ?? ''} cpu_cores=${effectiveCores} cpu_pct=${effectivePct} cpuset=${effectiveCpuset || ''} pinning=${effectivePinning || ''}`,
        ];
        if (cfg.hostname) {
            const cleanHost = cfg.hostname.replace(/[^a-zA-Z0-9.-]/g, '').slice(0, 63);
            if (cleanHost)
                lines.push(`lxc.uts.name = ${cleanHost}`);
        }
        if (cfg.autostart !== undefined) {
            lines.push(`lxc.start.auto = ${cfg.autostart ? 1 : 0}`);
        }
        if (cfg.nesting) {
            if (apparmorAvailable && fs_1.default.existsSync('/usr/share/lxc/config/nesting.conf')) {
                lines.push('lxc.include = /usr/share/lxc/config/nesting.conf');
            }
            else {
                lines.push('lxc.mount.auto =');
                lines.push('lxc.mount.auto = proc:mixed sys:rw cgroup:mixed');
            }
        }
        // Bind-mount cgroup-virtualized lxcfs /proc entries so `free -h`, `neofetch`, `top`, and `htop`
        // inside the container display the container's assigned RAM/Swap/CPU instead of host /proc!
        if (isSystemStore && fs_1.default.existsSync('/var/lib/lxcfs/proc/meminfo')) {
            const hasCommonLxcfsHook = stripped.includes('/usr/share/lxc/config/common.conf') &&
                fs_1.default.existsSync('/usr/share/lxc/config/common.conf.d/00-lxcfs.conf');
            if (!hasCommonLxcfsHook) {
                for (const procEntry of ['cpuinfo', 'diskstats', 'loadavg', 'meminfo', 'stat', 'swaps', 'uptime']) {
                    if (fs_1.default.existsSync(`/var/lib/lxcfs/proc/${procEntry}`)) {
                        lines.push(`lxc.mount.entry = /var/lib/lxcfs/proc/${procEntry} proc/${procEntry} none bind,rw,optional 0 0`);
                    }
                }
            }
        }
        const requestedProfile = (cfg.apparmorProfile || 'generated').replace(/[^a-zA-Z0-9_.-]/g, '');
        const effectiveAppArmor = apparmorAvailable && !cfg.kvmNesting ? requestedProfile || 'generated' : 'unconfined';
        lines.push(`lxc.apparmor.profile = ${effectiveAppArmor}`);
        if (cfg.kvmNesting) {
            if (isCgroupV2) {
                lines.push('lxc.cgroup2.devices.allow = c 10:232 rwm');
                lines.push('lxc.cgroup2.devices.allow = c 10:200 rwm');
            }
            else {
                lines.push('lxc.cgroup.devices.allow = c 10:232 rwm');
                lines.push('lxc.cgroup.devices.allow = c 10:200 rwm');
            }
            lines.push('lxc.mount.entry = /dev/kvm dev/kvm none bind,optional,create=file 0 0');
            lines.push('lxc.mount.entry = /dev/net/tun dev/net/tun none bind,optional,create=file 0 0');
        }
        if (isCgroupV2 && cgroupV2Controllers) {
            if (isSystemStore) {
                const baseCgDir = resolveHostBaseCgroupV2Dir();
                if (isUsableDomainCgroupDir(path_1.default.join(baseCgDir, 'hkvm.lxc'))) {
                    lines.push('lxc.cgroup.relative = 0');
                    lines.push('lxc.cgroup.dir = hkvm.lxc');
                }
            }
            if (cgroupV2Controllers.has('cpu')) {
                lines.push(`lxc.cgroup2.cpu.max = ${quotaUs} 100000`);
                if (cfg.cpuShares) {
                    const weight = Math.min(10000, Math.max(1, Math.round((cfg.cpuShares / 1024) * 100)));
                    lines.push(`lxc.cgroup2.cpu.weight = ${weight}`);
                }
            }
            if (cgroupV2Controllers.has('cpuset') && effectiveCpuset) {
                lines.push(`lxc.cgroup2.cpuset.cpus = ${effectiveCpuset}`);
            }
            if (cgroupV2Controllers.has('memory')) {
                if (effectiveRamMb) {
                    lines.push(`lxc.cgroup2.memory.max = ${effectiveRamMb}M`);
                }
                if (effectiveSwapMb !== undefined && isCgroupV2SwapSupported()) {
                    lines.push(`lxc.cgroup2.memory.swap.max = ${effectiveSwapMb}M`);
                }
            }
        }
        else if (!isCgroupV2) {
            lines.push(`lxc.cgroup.cpu.cfs_period_us = 100000`);
            lines.push(`lxc.cgroup.cpu.cfs_quota_us = ${quotaUs}`);
            if (cfg.cpuShares) {
                lines.push(`lxc.cgroup.cpu.shares = ${Math.max(64, cfg.cpuShares)}`);
            }
            if (effectiveCpuset) {
                lines.push(`lxc.cgroup.cpuset.cpus = ${effectiveCpuset}`);
            }
            if (effectiveRamMb) {
                lines.push(`lxc.cgroup.memory.limit_in_bytes = ${effectiveRamMb}M`);
            }
        }
        let configuredGuestIpv4 = null;
        let configuredGuestGateway = null;
        let activeBridgeInfo = null;
        if (cfg.bridge) {
            const safeBridge = middleware_1.SafeValidators.bridgeOrIface(cfg.bridge);
            const isSystemStore = this.isSystemLxcStore();
            const bridgeInfo = isSystemStore
                ? await this.ensureBridgeNetworkReady(safeBridge)
                : {
                    ready: true,
                    bridgeIp: null,
                    prefixLen: 24,
                    subnetCidr: null,
                    hasDhcpServer: true,
                    natConfigured: false,
                    dnsRelayPort: 0,
                };
            activeBridgeInfo = bridgeInfo;
            if (bridgeInfo.ready) {
                lines.push(`lxc.net.0.type = veth`);
                lines.push(`lxc.net.0.link = ${safeBridge}`);
                lines.push(`lxc.net.0.flags = up`);
                lines.push(`lxc.net.0.name = eth0`);
                if (cfg.macAddress && /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/.test(cfg.macAddress)) {
                    lines.push(`lxc.net.0.hwaddr = ${cfg.macAddress}`);
                }
                if (cfg.ipv4Address) {
                    configuredGuestIpv4 = cfg.ipv4Address.includes('/')
                        ? cfg.ipv4Address
                        : `${middleware_1.SafeValidators.ipv4(cfg.ipv4Address)}/24`;
                }
                else if (isSystemStore && !bridgeInfo.hasDhcpServer && bridgeInfo.bridgeIp) {
                    configuredGuestIpv4 = await this.allocateAutoBridgeIpv4(safeName, safeBridge, bridgeInfo.bridgeIp, bridgeInfo.prefixLen);
                }
                if (configuredGuestIpv4) {
                    lines.push(`lxc.net.0.ipv4.address = ${configuredGuestIpv4}`);
                }
                if (cfg.ipv4Gateway) {
                    configuredGuestGateway =
                        cfg.ipv4Gateway === 'auto' ? 'auto' : middleware_1.SafeValidators.ipv4(cfg.ipv4Gateway);
                }
                else if (configuredGuestIpv4) {
                    if (bridgeInfo.bridgeIp) {
                        configuredGuestGateway = bridgeInfo.bridgeIp;
                    }
                    else {
                        const [ipOnly, pfxRaw] = configuredGuestIpv4.split('/');
                        const pfx = parseInt(pfxRaw || '24', 10) || 24;
                        const sub = computeIpv4SubnetCidr(ipOnly, pfx);
                        if (sub) {
                            const netUint = ipv4ToUint32(sub.split('/')[0]);
                            const gwCandidate = uint32ToIpv4((netUint + 1) >>> 0);
                            configuredGuestGateway = gwCandidate !== ipOnly ? gwCandidate : 'auto';
                        }
                        else {
                            configuredGuestGateway = 'auto';
                        }
                    }
                }
                if (configuredGuestGateway) {
                    lines.push(`lxc.net.0.ipv4.gateway = ${configuredGuestGateway}`);
                }
                if (cfg.ipv6Address) {
                    lines.push(`lxc.net.0.ipv6.address = ${middleware_1.SafeValidators.ipv6OrCidr(cfg.ipv6Address)}`);
                }
            }
            else {
                // Host does not have bridge interface and kernel denied creating one (e.g. nested container host)
                lines.push(`lxc.net.0.type = none`);
            }
        }
        if (Array.isArray(cfg.mounts)) {
            for (const m of cfg.mounts) {
                const guestRel = middleware_1.SafeValidators.safeContainerSubpath(m.guestTarget).replace(/^\//, '');
                if (!guestRel)
                    continue;
                const hostReal = path_1.default.resolve(m.hostSource);
                const roOpt = m.readOnly ? ',ro' : '';
                lines.push(`lxc.mount.entry = ${hostReal} ${guestRel} none bind,create=dir${roOpt} 0 0`);
            }
        }
        lines.push(markerEnd);
        command_runner_1.privilegedFs.writeFileSync(configFile, `${stripped.trimEnd()}\n\n${lines.join('\n')}\n`, 0o640);
        const dnsServers = this.buildEffectiveGuestDnsList(activeBridgeInfo);
        // Ensure guest /etc/resolv.conf + netplan/networkd/interfaces match so DNS & routing work immediately
        this.configureGuestNetworkingAndDns(safeName, {
            ipv4Cidr: configuredGuestIpv4,
            gateway: configuredGuestGateway && configuredGuestGateway !== 'auto' ? configuredGuestGateway : null,
            useDhcp: !configuredGuestIpv4,
            dnsServers,
        });
    }
    buildEffectiveGuestDnsList(bridgeInfo) {
        const base = resolveGuestDnsServers();
        if (bridgeInfo && bridgeInfo.bridgeIp && bridgeInfo.dnsRelayPort > 0) {
            return [
                bridgeInfo.bridgeIp,
                ...base.filter((ip) => ip !== bridgeInfo.bridgeIp),
            ].slice(0, 3);
        }
        return base.slice(0, 3);
    }
    async prepareContainerNetworkPreStart(containerName, opts = {}) {
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        const netCfg = this.readContainerNetFromConfig(safeName);
        const bridge = middleware_1.SafeValidators.bridgeOrIface(netCfg.bridge || opts.fallbackBridge || 'lxcbr0');
        let ipv4Cidr = netCfg.ipv4Cidr;
        let gateway = netCfg.gateway;
        let natConfigured = false;
        let activeBridgeInfo = null;
        if (this.isSystemLxcStore()) {
            const bridgeInfo = await this.ensureBridgeNetworkReady(bridge);
            activeBridgeInfo = bridgeInfo;
            natConfigured = bridgeInfo.natConfigured;
            const configFile = path_1.default.join(this.getContainerDir(safeName), 'config');
            const curCfgText = command_runner_1.privilegedFs.existsSync(configFile)
                ? command_runner_1.privilegedFs.readTextSync(configFile)
                : '';
            const hadNetTypeNone = /^\s*lxc\.net\.0\.type\s*=\s*none\b/m.test(curCfgText);
            let runningWithoutIp = false;
            if (opts.forceAutoIpIfRunningWithoutIp && !ipv4Cidr) {
                const curInfo = await this.inspectContainer(safeName);
                if (curInfo.state === 'running' && curInfo.ips.length === 0) {
                    runningWithoutIp = true;
                }
            }
            const needsAutoIp = !ipv4Cidr &&
                Boolean(bridgeInfo.bridgeIp) &&
                (!bridgeInfo.hasDhcpServer || runningWithoutIp);
            if (needsAutoIp && bridgeInfo.bridgeIp) {
                const autoIp = await this.allocateAutoBridgeIpv4(safeName, bridge, bridgeInfo.bridgeIp, bridgeInfo.prefixLen);
                if (autoIp) {
                    ipv4Cidr = autoIp;
                    gateway = bridgeInfo.bridgeIp;
                }
            }
            if (!gateway && bridgeInfo.bridgeIp) {
                gateway = bridgeInfo.bridgeIp;
            }
            if (bridgeInfo.ready && curCfgText && (hadNetTypeNone || !netCfg.bridge || needsAutoIp)) {
                const markerEnd = '# --- END HKVM MANAGED CONFIG ---';
                const netLines = [
                    `lxc.net.0.type = veth`,
                    `lxc.net.0.link = ${bridge}`,
                    `lxc.net.0.flags = up`,
                    `lxc.net.0.name = eth0`,
                    ...(ipv4Cidr ? [`lxc.net.0.ipv4.address = ${ipv4Cidr}`] : []),
                    ...(gateway ? [`lxc.net.0.ipv4.gateway = ${gateway}`] : []),
                ].join('\n');
                const cleaned = curCfgText
                    .replace(/^\s*lxc\.net\.0(?:\.(?:type|link|flags|name|ipv4\.address|ipv4\.gateway))?\s*=.*$/gm, '')
                    .replace(/\n{3,}/g, '\n\n');
                const updated = cleaned.includes(markerEnd)
                    ? cleaned.replace(markerEnd, `${netLines}\n${markerEnd}`)
                    : `${cleaned.trimEnd()}\n${netLines}\n`;
                command_runner_1.privilegedFs.writeFileSync(configFile, updated, 0o640);
            }
        }
        const effectiveDns = this.buildEffectiveGuestDnsList(activeBridgeInfo);
        const dnsServers = this.configureGuestNetworkingAndDns(safeName, {
            ipv4Cidr,
            gateway: gateway && gateway !== 'auto' ? gateway : null,
            useDhcp: !ipv4Cidr,
            dnsServers: effectiveDns,
        });
        return {
            bridge,
            ipv4Cidr,
            gateway,
            dnsServers,
            dnsRelayPort: activeBridgeInfo?.dnsRelayPort || 0,
            natConfigured,
        };
    }
    /**
     * Ensures a running container's host-side `veth` peer is enslaved to `bridge` and `UP`
     * (recovers containers whose bridge was recreated or bounced while the container stayed running).
     */
    async ensureRunningVethAttachedToBridge(containerName, bridge) {
        if (!this.isSystemLxcStore() || !(0, command_runner_1.isBinaryAvailable)('lxc-attach') || !(0, command_runner_1.isBinaryAvailable)('ip')) {
            return { eth0Exists: true };
        }
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        const safeBridge = middleware_1.SafeValidators.bridgeOrIface(bridge);
        const linkRes = await (0, command_runner_1.runAllowlistedCommand)('lxc-attach', [...this.lxcPathArgs(), '-n', safeName, '--', 'ip', '-o', 'link', 'show', 'dev', 'eth0'], { timeoutMs: 5000, asRoot: true }).catch(() => null);
        if (!linkRes || linkRes.exitCode !== 0) {
            return { eth0Exists: false };
        }
        const peerMatch = linkRes.stdout.match(/\beth0@if(\d+):/);
        if (peerMatch) {
            const hostIfIndex = parseInt(peerMatch[1], 10);
            if (hostIfIndex > 0) {
                const hostLinks = await (0, command_runner_1.runAllowlistedCommand)('ip', ['-o', 'link', 'show'], {
                    timeoutMs: 4000,
                }).catch(() => null);
                if (hostLinks && hostLinks.stdout) {
                    for (const line of hostLinks.stdout.split('\n')) {
                        const m = line.match(new RegExp(`^${hostIfIndex}:\\s+([^:@\\s]+)`));
                        if (m) {
                            const hostVeth = middleware_1.SafeValidators.bridgeOrIface(m[1]);
                            await (0, command_runner_1.runAllowlistedCommand)('ip', ['link', 'set', 'dev', hostVeth, 'master', safeBridge], { timeoutMs: 4000, asRoot: true }).catch(() => undefined);
                            await (0, command_runner_1.runAllowlistedCommand)('ip', ['link', 'set', 'dev', hostVeth, 'up'], {
                                timeoutMs: 4000,
                                asRoot: true,
                            }).catch(() => undefined);
                            break;
                        }
                    }
                }
            }
        }
        return { eth0Exists: true };
    }
    async applyLiveGuestNetworkIfNeeded(containerName, ipv4Cidr, gateway, dnsServers, force = false) {
        if (!(0, command_runner_1.isBinaryAvailable)('lxc-attach'))
            return false;
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        const info = await this.inspectContainer(safeName);
        if (info.state !== 'running')
            return false;
        const rootOpt = { timeoutMs: 8000, asRoot: this.needsRootForStore() || undefined };
        let applied = false;
        await (0, command_runner_1.runAllowlistedCommand)('lxc-attach', [...this.lxcPathArgs(), '-n', safeName, '--', 'ip', 'link', 'set', 'eth0', 'up'], rootOpt).catch(() => undefined);
        if (ipv4Cidr) {
            const ipOnly = ipv4Cidr.split('/')[0];
            const cidrFull = ipv4Cidr.includes('/') ? ipv4Cidr : `${ipv4Cidr}/24`;
            if (force || !info.ips.includes(ipOnly)) {
                const addrRes = await (0, command_runner_1.runAllowlistedCommand)('lxc-attach', [...this.lxcPathArgs(), '-n', safeName, '--', 'ip', 'addr', 'replace', cidrFull, 'dev', 'eth0'], rootOpt).catch(() => null);
                if (addrRes && addrRes.exitCode === 0)
                    applied = true;
            }
            if (gateway && gateway !== 'auto') {
                const routeRes = await (0, command_runner_1.runAllowlistedCommand)('lxc-attach', [
                    ...this.lxcPathArgs(),
                    '-n',
                    safeName,
                    '--',
                    'ip',
                    'route',
                    'replace',
                    'default',
                    'via',
                    gateway,
                    'dev',
                    'eth0',
                ], rootOpt).catch(() => null);
                if (routeRes && routeRes.exitCode === 0)
                    applied = true;
            }
        }
        else if (gateway && gateway !== 'auto') {
            // Even when IP came via DHCP, ensure a default route exists on eth0
            const defCheck = await (0, command_runner_1.runAllowlistedCommand)('lxc-attach', [...this.lxcPathArgs(), '-n', safeName, '--', 'ip', '-4', 'route', 'show', 'default'], rootOpt).catch(() => null);
            if (defCheck && defCheck.exitCode === 0 && !defCheck.stdout.trim()) {
                await (0, command_runner_1.runAllowlistedCommand)('lxc-attach', [
                    ...this.lxcPathArgs(),
                    '-n',
                    safeName,
                    '--',
                    'ip',
                    'route',
                    'replace',
                    'default',
                    'via',
                    gateway,
                    'dev',
                    'eth0',
                ], rootOpt).catch(() => undefined);
            }
        }
        if (dnsServers.length > 0 && (force || this.isSystemLxcStore())) {
            const resolvBody = [
                '# Managed by TGVPANEL',
                ...dnsServers.map((ns) => `nameserver ${ns}`),
                'options timeout:2 attempts:2',
                '',
            ].join('\n');
            await (0, command_runner_1.runAllowlistedCommand)('lxc-attach', [...this.lxcPathArgs(), '-n', safeName, '--', 'rm', '-f', '/etc/resolv.conf'], rootOpt).catch(() => undefined);
            const teeRes = await (0, command_runner_1.runAllowlistedCommand)('lxc-attach', [...this.lxcPathArgs(), '-n', safeName, '--', 'tee', '/etc/resolv.conf'], { ...rootOpt, stdinData: resolvBody }).catch(() => null);
            if (teeRes && teeRes.exitCode === 0)
                applied = true;
            // Also push DNS servers into live systemd-resolved (if running inside Ubuntu/Debian guest)
            await (0, command_runner_1.runAllowlistedCommand)('lxc-attach', [...this.lxcPathArgs(), '-n', safeName, '--', 'resolvectl', 'dns', 'eth0', ...dnsServers], { ...rootOpt, timeoutMs: 4000 }).catch(() => undefined);
            await (0, command_runner_1.runAllowlistedCommand)('lxc-attach', [...this.lxcPathArgs(), '-n', safeName, '--', 'resolvectl', 'flush-caches'], { ...rootOpt, timeoutMs: 4000 }).catch(() => undefined);
        }
        return applied;
    }
    /**
     * Repairs host bridge/NAT/FORWARD/DNS-relay rules, upgrades `lxc.net.0.type = none` if needed,
     * auto-assigns a collision-free IPv4 if the container lacks one, re-enslaves orphaned host
     * `veth` peers (or restarts the container if `eth0` was never created), and applies IP/route/DNS
     * live inside the guest.
     */
    async repairContainerNetworking(containerName, fallbackBridge = 'lxcbr0') {
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        let pre = await this.prepareContainerNetworkPreStart(safeName, {
            forceAutoIpIfRunningWithoutIp: true,
            fallbackBridge,
        });
        let restartedForVeth = false;
        const beforeInfo = await this.inspectContainer(safeName);
        if (beforeInfo.state === 'running' && this.isSystemLxcStore()) {
            const vethCheck = await this.ensureRunningVethAttachedToBridge(safeName, pre.bridge);
            if (!vethCheck.eth0Exists) {
                // Container booted previously without an eth0 veth device (e.g. lxc.net.0.type = none):
                // restart it once so liblxc attaches the newly configured veth pair to the bridge.
                await this.stopContainer(safeName).catch(() => undefined);
                await this.startContainer(safeName);
                restartedForVeth = true;
                pre = await this.prepareContainerNetworkPreStart(safeName, {
                    forceAutoIpIfRunningWithoutIp: true,
                    fallbackBridge,
                });
            }
        }
        const liveApplied = await this.applyLiveGuestNetworkIfNeeded(safeName, pre.ipv4Cidr, pre.gateway, pre.dnsServers, true);
        const info = await this.inspectContainer(safeName);
        const resolvedIp = info.ips[0] || (pre.ipv4Cidr ? pre.ipv4Cidr.split('/')[0] : null) || info.configuredIpv4 || null;
        return {
            containerName: safeName,
            state: info.state,
            bridge: pre.bridge,
            ipv4Address: resolvedIp,
            gateway: pre.gateway && pre.gateway !== 'auto' ? pre.gateway : null,
            dnsServers: pre.dnsServers,
            dnsRelayPort: pre.dnsRelayPort || undefined,
            natConfigured: pre.natConfigured,
            liveApplied: liveApplied || restartedForVeth,
            restartedForVeth,
        };
    }
    async ensureHostIsolationReady() {
        if (!this.isSystemLxcStore())
            return;
        ensureCgroupV2SubtreeDelegation();
        await (0, command_runner_1.ensureLxcfsDaemonMounted)().catch(() => false);
    }
    parseManagedLimitsComment(configText) {
        const m = configText.match(/^#\s*hkvm\.limits:\s*(.+)$/m);
        if (!m)
            return null;
        const kv = {};
        for (const tok of m[1].trim().split(/\s+/)) {
            const eq = tok.indexOf('=');
            if (eq > 0) {
                kv[tok.slice(0, eq)] = tok.slice(eq + 1);
            }
        }
        return {
            ramMb: kv.ram_mb && /^\d+$/.test(kv.ram_mb) ? Number(kv.ram_mb) : undefined,
            swapMb: kv.swap_mb && /^\d+$/.test(kv.swap_mb) ? Number(kv.swap_mb) : undefined,
            cpuCores: kv.cpu_cores && /^\d+$/.test(kv.cpu_cores) ? Number(kv.cpu_cores) : undefined,
            cpuLimitPercent: kv.cpu_pct && /^\d+$/.test(kv.cpu_pct) ? Number(kv.cpu_pct) : undefined,
            cpuset: kv.cpuset || null,
            cpuPinning: kv.pinning || null,
        };
    }
    /**
     * Enforces RAM (`memory.max`), Swap (`memory.swap.max`), CFS CPU quota (`cpu.max`), and
     * CPU core pinning (`cpuset.cpus`) directly on the running container's live kernel cgroup v2
     * directory (resolved from `/proc/<init_pid>/cgroup`), with each controller applied independently
     * so an unsupported secondary knob (such as `memory.swap.max` or `devices.allow`) NEVER prevents
     * `memory.max`, `cpu.max`, or `cpuset.cpus` from taking effect.
     */
    async enforceLiveContainerCgroups(containerName, override) {
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        let targetCgDir = override?.cgroupDirOverride || null;
        if (!targetCgDir) {
            let pid = override?.pid ?? null;
            if (!pid) {
                const info = await this.inspectContainer(safeName).catch(() => null);
                if (!info || info.state !== 'running' || !info.pid)
                    return false;
                pid = info.pid;
            }
            targetCgDir =
                resolveContainerPayloadCgroupV2Dir(safeName, pid) || resolveLiveContainerCgroupV2Dir(pid);
        }
        if (!targetCgDir || !fs_1.default.existsSync(targetCgDir))
            return false;
        const configFile = path_1.default.join(this.getContainerDir(safeName), 'config');
        const saved = command_runner_1.privilegedFs.existsSync(configFile)
            ? this.parseManagedLimitsComment(command_runner_1.privilegedFs.readTextSync(configFile))
            : null;
        const ramMb = override?.ramMb ?? saved?.ramMb;
        const swapMb = override?.swapMb ?? saved?.swapMb;
        const cpuCores = override?.cpuCores ?? saved?.cpuCores;
        const cpuPct = Math.min(100, Math.max(5, Number(override?.cpuLimitPercent ?? saved?.cpuLimitPercent ?? 100)));
        const explicitPinning = override?.cpuPinning !== undefined ? override.cpuPinning : (saved?.cpuPinning ?? null);
        // Ensure ancestor cgroups between `/sys/fs/cgroup` and `targetCgDir` have controllers delegated
        // whenever those ancestors are valid domain cgroups with zero internal processes.
        try {
            const relParts = path_1.default
                .relative('/sys/fs/cgroup', targetCgDir)
                .split(path_1.default.sep)
                .filter(Boolean);
            let cursor = '/sys/fs/cgroup';
            for (let i = 0; i < relParts.length - 1; i++) {
                cursor = path_1.default.join(cursor, relParts[i]);
                const ctrlFile = path_1.default.join(cursor, 'cgroup.controllers');
                const subFile = path_1.default.join(cursor, 'cgroup.subtree_control');
                const procsFile = path_1.default.join(cursor, 'cgroup.procs');
                if (isUsableDomainCgroupDir(cursor) &&
                    fs_1.default.existsSync(ctrlFile) &&
                    fs_1.default.existsSync(subFile) &&
                    fs_1.default.existsSync(procsFile)) {
                    const procsTxt = fs_1.default.readFileSync(procsFile, 'utf8').trim();
                    if (!procsTxt) {
                        const avail = fs_1.default
                            .readFileSync(ctrlFile, 'utf8')
                            .trim()
                            .split(/\s+/)
                            .filter(Boolean);
                        const ordered = [
                            ...avail.filter((c) => !THREADED_CAPABLE_CONTROLLERS.has(c)),
                            ...avail.filter((c) => THREADED_CAPABLE_CONTROLLERS.has(c)),
                        ];
                        for (const ctrl of ordered) {
                            try {
                                command_runner_1.privilegedFs.writeFileSync(subFile, `+${ctrl}`);
                            }
                            catch {
                                // ignore
                            }
                        }
                    }
                }
            }
        }
        catch {
            // non-fatal
        }
        let appliedAny = false;
        if (ramMb && ramMb >= 64) {
            const memMaxFile = path_1.default.join(targetCgDir, 'memory.max');
            if (fs_1.default.existsSync(memMaxFile)) {
                try {
                    command_runner_1.privilegedFs.writeFileSync(memMaxFile, `${Math.round(ramMb * 1024 * 1024)}\n`);
                    appliedAny = true;
                }
                catch {
                    // ignore
                }
            }
        }
        if (swapMb !== undefined && swapMb >= 0) {
            const swapMaxFile = path_1.default.join(targetCgDir, 'memory.swap.max');
            if (fs_1.default.existsSync(swapMaxFile)) {
                try {
                    command_runner_1.privilegedFs.writeFileSync(swapMaxFile, `${Math.round(swapMb * 1024 * 1024)}\n`);
                    appliedAny = true;
                }
                catch {
                    // ignore
                }
            }
        }
        if (cpuCores && cpuCores >= 1) {
            const cpuMaxFile = path_1.default.join(targetCgDir, 'cpu.max');
            const quotaUs = Math.round(Math.max(1, cpuCores) * 100_000 * (cpuPct / 100));
            if (fs_1.default.existsSync(cpuMaxFile)) {
                try {
                    command_runner_1.privilegedFs.writeFileSync(cpuMaxFile, `${quotaUs} 100000\n`);
                    appliedAny = true;
                }
                catch {
                    // ignore
                }
            }
            const cpusetFile = path_1.default.join(targetCgDir, 'cpuset.cpus');
            const cpusetVal = selectContainerCpuset(safeName, cpuCores, readEffectiveHostCpuIds(), explicitPinning);
            if (cpusetVal && fs_1.default.existsSync(cpusetFile)) {
                try {
                    command_runner_1.privilegedFs.writeFileSync(cpusetFile, `${cpusetVal}\n`);
                    appliedAny = true;
                }
                catch {
                    // ignore
                }
            }
        }
        return appliedAny;
    }
    /**
     * Inspects both `<ct>/config` and the container's live kernel cgroup (`/proc/<pid>/cgroup`)
     * to determine whether the container needs its config refreshed, needs a restart out of an
     * undelegated cgroup (such as legacy `/hkvm.host/...`), or can have limits applied live in-place.
     */
    needsContainerCgroupRestartOrHeal(containerName, pid, desired) {
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        const cfgPath = path_1.default.join(this.getContainerDir(safeName), 'config');
        const curCfg = command_runner_1.privilegedFs.existsSync(cfgPath) ? command_runner_1.privilegedFs.readTextSync(cfgPath) : '';
        const isV2 = fs_1.default.existsSync('/sys/fs/cgroup/cgroup.controllers');
        const baseDir = isV2 ? resolveHostBaseCgroupV2Dir() : '/sys/fs/cgroup';
        const hasHkvmLxcDir = isV2 && isUsableDomainCgroupDir(path_1.default.join(baseDir, 'hkvm.lxc'));
        const missingLimitsComment = !curCfg.includes('# hkvm.limits:');
        const missingMemDirective = !curCfg.includes('memory.max') && !curCfg.includes('memory.limit_in_bytes');
        const missingCgroupDirDirective = hasHkvmLxcDir && !curCfg.includes('lxc.cgroup.dir = hkvm.lxc');
        const hasCommonLxcfsHook = curCfg.includes('/usr/share/lxc/config/common.conf') &&
            fs_1.default.existsSync('/usr/share/lxc/config/common.conf.d/00-lxcfs.conf');
        const missingLxcfsBind = fs_1.default.existsSync('/var/lib/lxcfs/proc/meminfo') &&
            !hasCommonLxcfsHook &&
            !curCfg.includes('/var/lib/lxcfs/proc/meminfo');
        const rewriteConfig = missingLimitsComment ||
            missingMemDirective ||
            missingCgroupDirDirective ||
            missingLxcfsBind;
        if (!pid || pid <= 1 || !isV2) {
            return {
                rewriteConfig,
                requiresRestart: Boolean(pid && pid > 1 && missingLxcfsBind),
                enforceLive: false,
            };
        }
        const cgDir = resolveContainerPayloadCgroupV2Dir(safeName, pid) || resolveLiveContainerCgroupV2Dir(pid);
        if (!cgDir) {
            return { rewriteConfig: true, requiresRestart: true, enforceLive: false };
        }
        // If the container is trapped inside legacy `/hkvm.host/...` or a cgroup where `memory.max`
        // is not delegated by its parent `subtree_control`, only a restart into `hkvm.lxc` can give it
        // a delegated payload cgroup with `memory.max` + `memory.stat` + `cpuset.cpus`!
        const memMaxPath = path_1.default.join(cgDir, 'memory.max');
        if (cgDir.includes('/hkvm.host/') || !fs_1.default.existsSync(memMaxPath) || missingLxcfsBind) {
            return { rewriteConfig: true, requiresRestart: true, enforceLive: false };
        }
        let enforceLive = false;
        try {
            const expectedBytes = String(Math.round(Math.max(64, desired.ramMb) * 1024 * 1024));
            const actualMemMax = fs_1.default.readFileSync(memMaxPath, 'utf8').trim();
            if (actualMemMax !== expectedBytes) {
                enforceLive = true;
            }
            const cpusetPath = path_1.default.join(cgDir, 'cpuset.cpus');
            const expectedCpuset = selectContainerCpuset(safeName, desired.cpuCores, readEffectiveHostCpuIds(), desired.cpuPinning);
            if (expectedCpuset && fs_1.default.existsSync(cpusetPath)) {
                const actualCpus = parseCpuListSpec(fs_1.default.readFileSync(cpusetPath, 'utf8'));
                const expectedCpus = parseCpuListSpec(expectedCpuset);
                if (actualCpus.length !== expectedCpus.length) {
                    enforceLive = true;
                }
            }
        }
        catch {
            enforceLive = true;
        }
        return { rewriteConfig, requiresRestart: false, enforceLive };
    }
    /**
     * Restores `lxc.cgroup.dir = hkvm.lxc` and `lxc.cgroup2.*` limit lines inside `<ct>/config`
     * when an earlier failed start stripped them prior to cgroup v2 `"domain threaded"` recovery.
     */
    restoreStrippedCgroupDirectivesIfReady(containerName) {
        try {
            const safeName = middleware_1.SafeValidators.containerName(containerName);
            if (!fs_1.default.existsSync('/sys/fs/cgroup/cgroup.controllers'))
                return false;
            const configFile = path_1.default.join(this.getContainerDir(safeName), 'config');
            if (!command_runner_1.privilegedFs.existsSync(configFile))
                return false;
            const curCfg = command_runner_1.privilegedFs.readTextSync(configFile);
            const saved = this.parseManagedLimitsComment(curCfg);
            if (!saved)
                return false;
            const baseDir = resolveHostBaseCgroupV2Dir();
            const lxcGroupDir = path_1.default.join(baseDir, 'hkvm.lxc');
            if (!isUsableDomainCgroupDir(lxcGroupDir))
                return false;
            const activeCtrls = readActiveCgroupV2Controllers(false);
            if (!activeCtrls || activeCtrls.size === 0)
                return false;
            const missingCgDir = !/^\s*lxc\.cgroup\.dir\s*=\s*hkvm\.lxc\s*$/m.test(curCfg);
            const missingMemMax = activeCtrls.has('memory') &&
                Boolean(saved.ramMb && saved.ramMb >= 64) &&
                !/^\s*lxc\.cgroup2\.memory\.max\s*=/m.test(curCfg);
            const missingCpuMax = activeCtrls.has('cpu') &&
                Boolean(saved.cpuCores && saved.cpuCores >= 1) &&
                !/^\s*lxc\.cgroup2\.cpu\.max\s*=/m.test(curCfg);
            if (!missingCgDir && !missingMemMax && !missingCpuMax)
                return false;
            const restoredLines = [];
            if (missingCgDir) {
                if (!/^\s*lxc\.cgroup\.relative\s*=/m.test(curCfg)) {
                    restoredLines.push('lxc.cgroup.relative = 0');
                }
                restoredLines.push('lxc.cgroup.dir = hkvm.lxc');
            }
            if (missingCpuMax && saved.cpuCores) {
                const cpuPct = Math.min(100, Math.max(5, Number(saved.cpuLimitPercent ?? 100)));
                const quotaUs = Math.round(Math.max(1, saved.cpuCores) * 100_000 * (cpuPct / 100));
                restoredLines.push(`lxc.cgroup2.cpu.max = ${quotaUs} 100000`);
            }
            if (activeCtrls.has('cpuset') &&
                saved.cpuCores &&
                !/^\s*lxc\.cgroup2\.cpuset\.cpus\s*=/m.test(curCfg)) {
                const cpusetVal = selectContainerCpuset(safeName, saved.cpuCores, readEffectiveHostCpuIds(), saved.cpuPinning ?? null);
                if (cpusetVal) {
                    restoredLines.push(`lxc.cgroup2.cpuset.cpus = ${cpusetVal}`);
                }
            }
            if (missingMemMax && saved.ramMb) {
                restoredLines.push(`lxc.cgroup2.memory.max = ${Math.round(saved.ramMb)}M`);
            }
            if (restoredLines.length === 0)
                return false;
            const endMarker = '# --- END HKVM MANAGED CONFIG ---';
            let nextCfg;
            if (curCfg.includes(endMarker)) {
                nextCfg = curCfg.replace(endMarker, `${restoredLines.join('\n')}\n${endMarker}`);
            }
            else {
                nextCfg = `${curCfg.trimEnd()}\n${restoredLines.join('\n')}\n`;
            }
            command_runner_1.privilegedFs.writeFileSync(configFile, nextCfg, 0o640);
            return true;
        }
        catch {
            return false;
        }
    }
    async startContainer(containerName) {
        this.assertLxcInstalled();
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        const info = await this.inspectContainer(safeName);
        if (info.state === 'running')
            return;
        if (info.state === 'frozen') {
            await this.unfreezeContainer(safeName);
            return;
        }
        if (this.isSystemLxcStore()) {
            ensureCgroupV2SubtreeDelegation();
            await (0, command_runner_1.ensureLxcfsDaemonMounted)().catch(() => false);
            // Self-heal `<ct>/config` if an earlier failed start stripped `lxc.cgroup.dir = hkvm.lxc` or
            // `lxc.cgroup2.*` lines before cgroup v2 `"domain threaded"` recovery took effect.
            this.restoreStrippedCgroupDirectivesIfReady(safeName);
        }
        await this.ensureExistingQuotaDiskMounted(safeName).catch(() => false);
        const preNet = await this.prepareContainerNetworkPreStart(safeName).catch(() => null);
        const logFile = command_runner_1.privilegedFs.existsSync('/var/log/lxc')
            ? `/var/log/lxc/${safeName}.log`
            : path_1.default.join(this.getContainerDir(safeName), `${safeName}.log`);
        const runStart = () => {
            if (this.isSystemLxcStore()) {
                // Clean up any stale empty monitor/payload cgroups left by an aborted attempt
                ensureCgroupV2SubtreeDelegation();
            }
            return (0, command_runner_1.runAllowlistedCommand)('lxc-start', [...this.lxcPathArgs(), '-n', safeName, '-d', '-l', 'ERROR', '-o', logFile], {
                timeoutMs: 30_000,
                asRoot: this.needsRootForStore() || undefined,
            });
        };
        let res = await runStart();
        if (res.exitCode !== 0) {
            let logTail = '';
            if (command_runner_1.privilegedFs.existsSync(logFile)) {
                try {
                    logTail = command_runner_1.privilegedFs.readTextSync(logFile).trim().split('\n').slice(-15).join('\n');
                }
                catch {
                    // ignore
                }
            }
            const combinedDiag = `${res.stderr}\n${res.stdout}\n${logTail}`;
            const configFile = path_1.default.join(this.getContainerDir(safeName), 'config');
            if (/cgroup|limits|devices/i.test(combinedDiag) && command_runner_1.privilegedFs.existsSync(configFile)) {
                try {
                    const originalCfgBeforeRetry = command_runner_1.privilegedFs.readTextSync(configFile);
                    let curCfg = originalCfgBeforeRetry;
                    const tryStripPattern = async (pattern) => {
                        if (res.exitCode === 0)
                            return;
                        const nextCfg = curCfg.replace(pattern, '');
                        if (nextCfg !== curCfg) {
                            command_runner_1.privilegedFs.writeFileSync(configFile, nextCfg, 0o640);
                            curCfg = nextCfg;
                            res = await runStart();
                        }
                    };
                    // Stage 1: Strip ONLY `devices.allow` / `devices.deny` (eBPF device rules often fail in nested cgroups)
                    await tryStripPattern(/^\s*lxc\.cgroup2?\.devices\.[a-zA-Z0-9_.-]+\s*=.*$/gm);
                    // Stage 2: Strip secondary `memory.swap.*` & `cpu.weight` while preserving `memory.max`, `cpu.max`, and `cpuset.cpus`
                    await tryStripPattern(/^\s*lxc\.cgroup2?\.(?:memory\.swap\.[a-zA-Z0-9_.-]+|cpu\.weight)\s*=.*$/gm);
                    // Stage 3: Strip `lxc.cgroup.dir` / `lxc.cgroup.relative` on older LXC versions while STILL keeping `memory.max` & `cpuset.cpus`
                    await tryStripPattern(/^\s*lxc\.cgroup\.(?:dir|relative)\s*=.*$/gm);
                    // Stage 4: Strip `cpuset.*` while keeping `memory.max` and `cpu.max`
                    await tryStripPattern(/^\s*lxc\.cgroup2?\.cpuset\.[a-zA-Z0-9_.-]+\s*=.*$/gm);
                    // Stage 5: Last-resort fallback on unprivileged kernels without any cgroup delegation
                    await tryStripPattern(/^\s*lxc\.cgroup2?\.[a-zA-Z0-9_.-]+\s*=.*$/gm);
                    // Never leave `<ct>/config` permanently stripped on disk if all retry stages still failed!
                    if (res.exitCode !== 0 && curCfg !== originalCfgBeforeRetry) {
                        command_runner_1.privilegedFs.writeFileSync(configFile, originalCfgBeforeRetry, 0o640);
                    }
                }
                catch {
                    // ignore config rewrite error and surface original failure
                }
            }
            if (res.exitCode !== 0) {
                let logDetails = '';
                if (command_runner_1.privilegedFs.existsSync(logFile)) {
                    try {
                        const tail = command_runner_1.privilegedFs.readTextSync(logFile).trim().split('\n').slice(-12).join('\n');
                        if (tail)
                            logDetails = ` | Log: ${tail}`;
                    }
                    catch {
                        // ignore
                    }
                }
                throw new Error(`lxc-start failed: ${(res.stderr || res.stdout).trim()}${logDetails}`);
            }
        }
        if (this.isSystemLxcStore()) {
            // Directly enforce `memory.max`, `cpu.max`, and `cpuset.cpus` on the live payload cgroup
            // so `neofetch` / `free -h` / `nproc` ALWAYS see exact limits even if an optional directive was skipped!
            await this.enforceLiveContainerCgroups(safeName).catch(() => false);
        }
        if (preNet && this.isSystemLxcStore()) {
            await this.applyLiveGuestNetworkIfNeeded(safeName, preNet.ipv4Cidr, preNet.gateway, preNet.dnsServers, false).catch(() => undefined);
        }
    }
    async stopContainer(containerName, force = false) {
        this.assertLxcInstalled();
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        const info = await this.inspectContainer(safeName);
        if (info.state === 'stopped' || info.state === 'missing')
            return;
        const args = force
            ? [...this.lxcPathArgs(), '-n', safeName, '-k']
            : [...this.lxcPathArgs(), '-n', safeName, '-t', '15'];
        const res = await (0, command_runner_1.runAllowlistedCommand)('lxc-stop', args, {
            timeoutMs: 25_000,
            asRoot: this.needsRootForStore() || undefined,
        });
        if (res.exitCode !== 0) {
            const killRes = await (0, command_runner_1.runAllowlistedCommand)('lxc-stop', [...this.lxcPathArgs(), '-n', safeName, '-k'], {
                timeoutMs: 10_000,
                asRoot: this.needsRootForStore() || undefined,
            });
            if (killRes.exitCode !== 0) {
                throw new Error(`lxc-stop failed: ${killRes.stderr || res.stderr}`);
            }
        }
    }
    async restartContainer(containerName) {
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        await this.stopContainer(safeName, false);
        await this.startContainer(safeName);
    }
    async freezeContainer(containerName) {
        this.assertLxcInstalled();
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        const res = await (0, command_runner_1.runAllowlistedCommand)('lxc-freeze', [...this.lxcPathArgs(), '-n', safeName], {
            timeoutMs: 15_000,
            asRoot: this.needsRootForStore() || undefined,
        });
        if (res.exitCode !== 0) {
            throw new Error(`lxc-freeze failed: ${res.stderr || res.stdout}`);
        }
    }
    async unfreezeContainer(containerName) {
        this.assertLxcInstalled();
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        const res = await (0, command_runner_1.runAllowlistedCommand)('lxc-unfreeze', [...this.lxcPathArgs(), '-n', safeName], {
            timeoutMs: 15_000,
            asRoot: this.needsRootForStore() || undefined,
        });
        if (res.exitCode !== 0) {
            throw new Error(`lxc-unfreeze failed: ${res.stderr || res.stdout}`);
        }
    }
    async destroyContainer(containerName) {
        this.assertLxcInstalled();
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        await this.stopContainer(safeName, true).catch(() => undefined);
        await this.unmountQuotaDiskIfMounted(safeName, true).catch(() => undefined);
        const res = await (0, command_runner_1.runAllowlistedCommand)('lxc-destroy', [...this.lxcPathArgs(), '-n', safeName, '-f'], {
            timeoutMs: 60_000,
            asRoot: this.needsRootForStore() || undefined,
        });
        if (res.exitCode !== 0) {
            const ctDir = this.getContainerDir(safeName);
            if (!command_runner_1.privilegedFs.existsSync(ctDir))
                return;
            throw new Error(`lxc-destroy failed: ${res.stderr || res.stdout}`);
        }
    }
    async reinstallContainer(spec) {
        const safeName = middleware_1.SafeValidators.containerName(spec.containerName);
        const info = await this.inspectContainer(safeName);
        if (info.state !== 'missing') {
            await this.destroyContainer(safeName);
        }
        else {
            await this.unmountQuotaDiskIfMounted(safeName, true).catch(() => undefined);
        }
        return this.createContainer(spec);
    }
    async updateContainerResources(containerName, update) {
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        await this.writeManagedConfigSection(safeName, update);
        // Apply live cgroup limits immediately if container is running (direct kernel cgroupfs + lxc-cgroup)
        const info = await this.inspectContainer(safeName);
        if (info.state === 'running') {
            await this.enforceLiveContainerCgroups(safeName, {
                ramMb: update.ramMb,
                swapMb: update.swapMb,
                cpuCores: update.cpuCores,
                cpuLimitPercent: update.cpuLimitPercent,
                cpuPinning: update.cpuPinning,
                pid: info.pid,
            }).catch(() => false);
        }
        if (info.state === 'running' && (0, command_runner_1.isBinaryAvailable)('lxc-cgroup')) {
            const isV2 = fs_1.default.existsSync('/sys/fs/cgroup/cgroup.controllers');
            const rootOpt = { timeoutMs: 5000, asRoot: this.needsRootForStore() || undefined };
            if (update.ramMb) {
                const key = isV2 ? 'memory.max' : 'memory.limit_in_bytes';
                await (0, command_runner_1.runAllowlistedCommand)('lxc-cgroup', [...this.lxcPathArgs(), '-n', safeName, key, `${Math.max(64, update.ramMb)}M`], rootOpt).catch(() => undefined);
            }
            if (update.swapMb !== undefined && isV2 && isCgroupV2SwapSupported()) {
                await (0, command_runner_1.runAllowlistedCommand)('lxc-cgroup', [...this.lxcPathArgs(), '-n', safeName, 'memory.swap.max', `${Math.max(0, update.swapMb)}M`], rootOpt).catch(() => undefined);
            }
            if (update.cpuCores) {
                const pct = Math.min(100, Math.max(5, Number(update.cpuLimitPercent || 100)));
                const quotaUs = Math.round(Math.max(1, update.cpuCores) * 100_000 * (pct / 100));
                if (isV2) {
                    await (0, command_runner_1.runAllowlistedCommand)('lxc-cgroup', [...this.lxcPathArgs(), '-n', safeName, 'cpu.max', `${quotaUs} 100000`], rootOpt).catch(() => undefined);
                }
                else {
                    await (0, command_runner_1.runAllowlistedCommand)('lxc-cgroup', [...this.lxcPathArgs(), '-n', safeName, 'cpu.cfs_quota_us', `${quotaUs}`], rootOpt).catch(() => undefined);
                }
                const cpuset = selectContainerCpuset(safeName, update.cpuCores, readEffectiveHostCpuIds(), update.cpuPinning);
                if (cpuset) {
                    await (0, command_runner_1.runAllowlistedCommand)('lxc-cgroup', [...this.lxcPathArgs(), '-n', safeName, 'cpuset.cpus', cpuset], rootOpt).catch(() => undefined);
                }
            }
        }
        // Apply disk quota volume provisioning or live online resize (`truncate` + `losetup -c` + `resize2fs`)
        if (update.diskGb && update.diskGb >= 1 && this.isSystemLxcStore()) {
            const hasLoopAlready = command_runner_1.privilegedFs.existsSync(this.getQuotaDiskImagePath(safeName));
            if (hasLoopAlready) {
                await this.ensureContainerQuotaDisk(safeName, update.diskGb).catch(() => false);
            }
            else {
                // Existing plain `dir` container without a quota volume yet: convert cleanly (brief stop/start if running)
                const wasRunning = info.state === 'running';
                if (wasRunning) {
                    await this.stopContainer(safeName).catch(() => undefined);
                }
                await this.ensureContainerQuotaDisk(safeName, update.diskGb).catch(() => false);
                if (wasRunning) {
                    await this.startContainer(safeName).catch(() => undefined);
                }
            }
        }
    }
    /**
     * Resets root password inside container using `chpasswd` over stdin (`shell: false`),
     * with offline `/etc/shadow` SHA-512 hash fallback when container is stopped.
     * Zero shell interpolation of password characters.
     */
    async setRootPassword(containerName, newPassword) {
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        if (!newPassword || newPassword.includes('\n') || newPassword.includes('\0')) {
            throw new Error('Password contains invalid control characters.');
        }
        const info = await this.inspectContainer(safeName);
        if (info.state !== 'running') {
            const updatedOffline = await this.applyOfflineRootPasswordHash(safeName, newPassword);
            if (updatedOffline)
                return;
            throw new Error(`Container "${safeName}" is not running and /etc/shadow could not be updated.`);
        }
        this.assertLxcInstalled();
        const res = await (0, command_runner_1.runAllowlistedCommand)('lxc-attach', [...this.lxcPathArgs(), '-n', safeName, '--', 'chpasswd'], {
            stdinData: `root:${newPassword}\n`,
            timeoutMs: 10_000,
            asRoot: this.needsRootForStore() || undefined,
        });
        if (res.exitCode !== 0) {
            const fallback = await this.applyOfflineRootPasswordHash(safeName, newPassword);
            if (!fallback) {
                throw new Error(`Failed to update container root password: ${res.stderr || res.stdout}`);
            }
        }
    }
    async injectSshPublicKey(containerName, publicKey) {
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        const trimmed = publicKey.trim();
        if (!/^(ssh-(rsa|ed25519)|ecdsa-sha2-nistp(256|384|521))\s+[A-Za-z0-9+/=]+/.test(trimmed)) {
            throw new Error('Invalid OpenSSH public key format.');
        }
        const rootfs = this.getRootfsDir(safeName);
        if (!command_runner_1.privilegedFs.existsSync(rootfs)) {
            throw new Error(`Container rootfs does not exist at ${rootfs}`);
        }
        const sshDir = this.resolveConfinedRootfsPath(safeName, '/root/.ssh');
        command_runner_1.privilegedFs.mkdirpSync(sshDir, 0o700);
        const authKeysPath = path_1.default.join(sshDir, 'authorized_keys');
        const existing = command_runner_1.privilegedFs.existsSync(authKeysPath)
            ? command_runner_1.privilegedFs.readTextSync(authKeysPath)
            : '';
        if (!existing.includes(trimmed)) {
            const nextContent = existing
                ? `${existing.replace(/\n*$/, '\n')}${trimmed}\n`
                : `${trimmed}\n`;
            command_runner_1.privilegedFs.writeFileSync(authKeysPath, nextContent, 0o600);
        }
    }
    async getContainerProcesses(containerName) {
        this.assertLxcInstalled();
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        const res = await (0, command_runner_1.runAllowlistedCommand)('lxc-attach', [
            ...this.lxcPathArgs(),
            '-n',
            safeName,
            '--',
            'ps',
            '-eo',
            'pid,user,pcpu,pmem,comm',
        ], {
            timeoutMs: 8000,
            asRoot: this.needsRootForStore() || undefined,
        });
        if (res.exitCode === 0) {
            return res.stdout
                .trim()
                .split('\n')
                .map((l) => l.trim())
                .filter((l) => l && !/^pid\b/i.test(l))
                .map((line) => {
                const cols = line.split(/\s+/);
                return {
                    pid: cols[0] || '',
                    user: cols[1] || '',
                    cpu: cols[2] || '0.0',
                    mem: cols[3] || '0.0',
                    command: cols.slice(4).join(' '),
                };
            });
        }
        // Fallback for BusyBox/Alpine `ps` where `-eo pcpu,pmem` is unsupported
        const bbRes = await (0, command_runner_1.runAllowlistedCommand)('lxc-attach', [...this.lxcPathArgs(), '-n', safeName, '--', 'ps', '-o', 'pid,user,comm'], {
            timeoutMs: 8000,
            asRoot: this.needsRootForStore() || undefined,
        });
        if (bbRes.exitCode !== 0)
            return [];
        return bbRes.stdout
            .trim()
            .split('\n')
            .map((l) => l.trim())
            .filter((l) => l && !/^pid\b/i.test(l))
            .map((line) => {
            const cols = line.split(/\s+/);
            return {
                pid: cols[0] || '',
                user: cols[1] || '',
                cpu: '0.0',
                mem: '0.0',
                command: cols.slice(2).join(' '),
            };
        });
    }
    async getContainerLogs(containerName, maxLines = 200) {
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        const candidates = [
            `/var/log/lxc/${safeName}.log`,
            path_1.default.join(this.getContainerDir(safeName), `${safeName}.log`),
        ];
        for (const file of candidates) {
            if (command_runner_1.privilegedFs.existsSync(file)) {
                try {
                    const content = command_runner_1.privilegedFs.readTextSync(file);
                    return content.split('\n').slice(-maxLines).join('\n');
                }
                catch {
                    // ignore unreadable log candidate
                }
            }
        }
        return '';
    }
    /**
     * Resolves a user-supplied path strictly within `<lxcBaseDir>/<container>/rootfs`,
     * blocking both `..` traversal and symlink escapes outside `rootfs`.
     */
    resolveConfinedRootfsPath(containerName, subPath) {
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        const rootfs = path_1.default.resolve(this.getRootfsDir(safeName));
        if (!command_runner_1.privilegedFs.existsSync(rootfs)) {
            throw new Error(`Container rootfs does not exist for "${safeName}".`);
        }
        const realRootfs = command_runner_1.privilegedFs.realpathSync(rootfs);
        const safeRel = middleware_1.SafeValidators.safeContainerSubpath(subPath).replace(/^\//, '');
        const joined = path_1.default.resolve(realRootfs, safeRel);
        if (joined !== realRootfs && !joined.startsWith(realRootfs + path_1.default.sep)) {
            throw new Error('Path traversal outside container rootfs denied.');
        }
        // Walk every existing path segment from rootfs downward to block intermediate or broken symlink escapes
        const segments = safeRel.split('/').filter(Boolean);
        let cursor = realRootfs;
        for (const seg of segments) {
            cursor = path_1.default.join(cursor, seg);
            let meta;
            try {
                meta = command_runner_1.privilegedFs.lstatMetaSync(cursor);
            }
            catch {
                break;
            }
            if (meta.isSymbolicLink) {
                let realTarget;
                try {
                    realTarget = command_runner_1.privilegedFs.realpathSync(cursor);
                }
                catch {
                    throw new Error('Symlink escape outside container rootfs denied.');
                }
                if (realTarget !== realRootfs && !realTarget.startsWith(realRootfs + path_1.default.sep)) {
                    throw new Error('Symlink escape outside container rootfs denied.');
                }
            }
        }
        return joined;
    }
    listRootfsDirectory(containerName, subPath = '/') {
        const targetDir = this.resolveConfinedRootfsPath(containerName, subPath);
        const cleanRel = middleware_1.SafeValidators.safeContainerSubpath(subPath);
        const names = command_runner_1.privilegedFs.readdirNamesSync(targetDir);
        return names.map((name) => {
            const childPath = path_1.default.join(targetDir, name);
            let size = 0;
            let modifiedAt = new Date(0).toISOString();
            let isDirectory = false;
            try {
                const st = command_runner_1.privilegedFs.lstatMetaSync(childPath);
                size = st.size;
                modifiedAt = st.mtimeIso;
                isDirectory = st.isDirectory;
            }
            catch {
                // ignore broken symlink stat
            }
            return {
                name,
                path: cleanRel === '/' ? `/${name}` : `${cleanRel}/${name}`,
                isDirectory,
                size,
                modifiedAt,
            };
        });
    }
    readRootfsFile(containerName, subPath, maxBytes = 2 * 1024 * 1024) {
        const target = this.resolveConfinedRootfsPath(containerName, subPath);
        const st = command_runner_1.privilegedFs.lstatMetaSync(target);
        if (st.isSymbolicLink || !st.isFile) {
            throw new Error('Target is not a regular file.');
        }
        if (st.size > maxBytes) {
            throw new Error(`File exceeds maximum inline read size (${maxBytes} bytes).`);
        }
        return command_runner_1.privilegedFs.readFileSync(target, maxBytes);
    }
    writeRootfsFile(containerName, subPath, data) {
        const target = this.resolveConfinedRootfsPath(containerName, subPath);
        if (command_runner_1.privilegedFs.existsSync(target) && command_runner_1.privilegedFs.lstatMetaSync(target).isSymbolicLink) {
            throw new Error('Refusing to overwrite symlink inside container rootfs.');
        }
        command_runner_1.privilegedFs.mkdirpSync(path_1.default.dirname(target));
        command_runner_1.privilegedFs.writeFileSync(target, data);
    }
    deleteRootfsEntry(containerName, subPath) {
        const cleanRel = middleware_1.SafeValidators.safeContainerSubpath(subPath);
        if (cleanRel === '/') {
            throw new Error('Refusing to delete container root directory.');
        }
        const target = this.resolveConfinedRootfsPath(containerName, cleanRel);
        command_runner_1.privilegedFs.rmRecursiveSync(target);
    }
}
exports.LxcContainerManager = LxcContainerManager;
