import os from 'os';
import { detectHostCapabilities, HostCapabilities } from './command-runner';

export interface NodeHealthReport {
  status: 'online' | 'degraded';
  agentVersion: string;
  hostname: string;
  uptimeSeconds: number;
  agentUptimeSeconds: number;
  agentTimeEpochSec: number;
  interactiveShellEnabled: boolean;
  timestamp: string;
  capabilities: HostCapabilities;
  warnings: string[];
}

const AGENT_STARTED_AT = Date.now();
export const AGENT_VERSION = '3.0.0';

let cachedCapabilities: { data: HostCapabilities; expiresAt: number } | null = null;

export async function getNodeHealthReport(
  forceRefresh = false,
  options?: { interactiveShellEnabled?: boolean }
): Promise<NodeHealthReport> {
  const now = Date.now();
  if (forceRefresh || !cachedCapabilities || cachedCapabilities.expiresAt <= now) {
    const caps = await detectHostCapabilities();
    cachedCapabilities = { data: caps, expiresAt: now + 60_000 };
  }

  const capabilities = cachedCapabilities.data;
  const warnings: string[] = [];

  if (!capabilities.kvmAvailable && !capabilities.lxcAvailable) {
    warnings.push(
      'Neither QEMU/KVM nor LXC userland utilities are installed on this host. Management plane is online in controller-only mode until hypervisor packages are installed.'
    );
  } else {
    if (capabilities.qemuSystemAvailable && !capabilities.kvmDevicePresent) {
      warnings.push(
        '/dev/kvm is unavailable on this host; QEMU instances will fall back to TCG software emulation.'
      );
    }
  }

  const interactiveShellEnabled =
    options?.interactiveShellEnabled ??
    (process.env.TGVPANEL_ENABLE_NODE_SHELL === 'true' ||
      process.env.HKVM_ENABLE_NODE_SHELL === 'true');

  return {
    status: 'online',
    agentVersion: AGENT_VERSION,
    hostname: os.hostname(),
    uptimeSeconds: Math.floor(os.uptime()),
    agentUptimeSeconds: Math.floor((now - AGENT_STARTED_AT) / 1000),
    agentTimeEpochSec: Math.floor(now / 1000),
    interactiveShellEnabled,
    timestamp: new Date(now).toISOString(),
    capabilities,
    warnings,
  };
}
