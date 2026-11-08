"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AGENT_VERSION = void 0;
exports.getNodeHealthReport = getNodeHealthReport;
const os_1 = __importDefault(require("os"));
const command_runner_1 = require("./command-runner");
const AGENT_STARTED_AT = Date.now();
exports.AGENT_VERSION = '3.0.0';
let cachedCapabilities = null;
async function getNodeHealthReport(forceRefresh = false, options) {
    const now = Date.now();
    if (forceRefresh || !cachedCapabilities || cachedCapabilities.expiresAt <= now) {
        const caps = await (0, command_runner_1.detectHostCapabilities)();
        cachedCapabilities = { data: caps, expiresAt: now + 60_000 };
    }
    const capabilities = cachedCapabilities.data;
    const warnings = [];
    if (!capabilities.kvmAvailable && !capabilities.lxcAvailable) {
        warnings.push('Neither QEMU/KVM nor LXC userland utilities are installed on this host. Management plane is online in controller-only mode until hypervisor packages are installed.');
    }
    else {
        if (capabilities.qemuSystemAvailable && !capabilities.kvmDevicePresent) {
            warnings.push('/dev/kvm is unavailable on this host; QEMU instances will fall back to TCG software emulation.');
        }
    }
    const interactiveShellEnabled = options?.interactiveShellEnabled ??
        (process.env.TGVPANEL_ENABLE_NODE_SHELL === 'true' ||
            process.env.HKVM_ENABLE_NODE_SHELL === 'true');
    return {
        status: 'online',
        agentVersion: exports.AGENT_VERSION,
        hostname: os_1.default.hostname(),
        uptimeSeconds: Math.floor(os_1.default.uptime()),
        agentUptimeSeconds: Math.floor((now - AGENT_STARTED_AT) / 1000),
        agentTimeEpochSec: Math.floor(now / 1000),
        interactiveShellEnabled,
        timestamp: new Date(now).toISOString(),
        capabilities,
        warnings,
    };
}
