import fs from 'fs';
import os from 'os';
import { runAllowlistedCommand } from './command-runner';

export interface HostResourceStats {
  timestamp: string;
  hostname: string;
  cpuModel: string;
  cpuCores: number;
  cpuPercent: number;
  loadAvg1: number;
  loadAvg5: number;
  loadAvg15: number;
  ramTotalMb: number;
  ramUsedMb: number;
  ramAvailableMb: number;
  ramPercent: number;
  swapTotalMb: number;
  swapUsedMb: number;
  diskTotalGb: number;
  diskUsedGb: number;
  diskAvailableGb: number;
  diskPercent: number;
  netRxBytes: number;
  netTxBytes: number;
  netRxRateBps: number;
  netTxRateBps: number;
  uptimeSeconds: number;
}

interface CpuJiffies {
  idle: number;
  total: number;
}

export class HostStatsCollector {
  private prevCpu: CpuJiffies | null = null;
  private prevNet: { rx: number; tx: number; ts: number } | null = null;

  constructor() {
    this.prevCpu = this.readProcStatCpu();
    const net = this.readProcNetDev();
    this.prevNet = { rx: net.rxBytes, tx: net.txBytes, ts: Date.now() };
  }

  private readProcStatCpu(): CpuJiffies | null {
    try {
      const content = fs.readFileSync('/proc/stat', 'utf8');
      const firstLine = content.split('\n').find((l) => l.startsWith('cpu '));
      if (!firstLine) return null;
      const parts = firstLine
        .trim()
        .split(/\s+/)
        .slice(1)
        .map((n) => parseInt(n, 10) || 0);
      const user = parts[0] || 0;
      const nice = parts[1] || 0;
      const system = parts[2] || 0;
      const idle = parts[3] || 0;
      const iowait = parts[4] || 0;
      const irq = parts[5] || 0;
      const softirq = parts[6] || 0;
      const steal = parts[7] || 0;
      const idleAll = idle + iowait;
      const total = user + nice + system + idleAll + irq + softirq + steal;
      return { idle: idleAll, total };
    } catch {
      return null;
    }
  }

  private readProcMeminfo() {
    try {
      const content = fs.readFileSync('/proc/meminfo', 'utf8');
      const map = new Map<string, number>();
      for (const line of content.split('\n')) {
        const m = line.match(/^([A-Za-z0-9_()]+):\s+(\d+)/);
        if (m) map.set(m[1], parseInt(m[2], 10)); // kB
      }
      const memTotalKb = map.get('MemTotal') || Math.round(os.totalmem() / 1024);
      const memAvailableKb =
        map.get('MemAvailable') ??
        (map.get('MemFree') || 0) + (map.get('Buffers') || 0) + (map.get('Cached') || 0);
      const memUsedKb = Math.max(0, memTotalKb - memAvailableKb);
      const swapTotalKb = map.get('SwapTotal') || 0;
      const swapFreeKb = map.get('SwapFree') || 0;
      const swapUsedKb = Math.max(0, swapTotalKb - swapFreeKb);

      return {
        ramTotalMb: Math.round(memTotalKb / 1024),
        ramUsedMb: Math.round(memUsedKb / 1024),
        ramAvailableMb: Math.round(memAvailableKb / 1024),
        ramPercent: memTotalKb > 0 ? Number(((memUsedKb / memTotalKb) * 100).toFixed(2)) : 0,
        swapTotalMb: Math.round(swapTotalKb / 1024),
        swapUsedMb: Math.round(swapUsedKb / 1024),
      };
    } catch {
      const totalMb = Math.round(os.totalmem() / (1024 * 1024));
      const freeMb = Math.round(os.freemem() / (1024 * 1024));
      const usedMb = Math.max(0, totalMb - freeMb);
      return {
        ramTotalMb: totalMb,
        ramUsedMb: usedMb,
        ramAvailableMb: freeMb,
        ramPercent: totalMb > 0 ? Number(((usedMb / totalMb) * 100).toFixed(2)) : 0,
        swapTotalMb: 0,
        swapUsedMb: 0,
      };
    }
  }

  private readProcNetDev(): { rxBytes: number; txBytes: number } {
    try {
      const content = fs.readFileSync('/proc/net/dev', 'utf8');
      let rxBytes = 0;
      let txBytes = 0;
      for (const line of content.split('\n').slice(2)) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        const [ifacePart, statsPart] = trimmed.split(':');
        if (!statsPart) continue;
        const iface = ifacePart.trim();
        if (iface === 'lo') continue;
        const cols = statsPart.trim().split(/\s+/);
        rxBytes += parseInt(cols[0] || '0', 10) || 0;
        txBytes += parseInt(cols[8] || '0', 10) || 0;
      }
      return { rxBytes, txBytes };
    } catch {
      return { rxBytes: 0, txBytes: 0 };
    }
  }

  private async readRootDiskUsage(targetPath = '/') {
    const res = await runAllowlistedCommand('df', ['-P', '-B1', targetPath], { timeoutMs: 5000 });
    if (res.exitCode === 0) {
      const lines = res.stdout.trim().split('\n');
      const dataLine = lines[lines.length - 1] || '';
      const cols = dataLine.trim().split(/\s+/);
      if (cols.length >= 5) {
        const totalBytes = parseInt(cols[1], 10) || 0;
        const usedBytes = parseInt(cols[2], 10) || 0;
        const availBytes = parseInt(cols[3], 10) || 0;
        const gb = 1024 * 1024 * 1024;
        return {
          diskTotalGb: Number((totalBytes / gb).toFixed(2)),
          diskUsedGb: Number((usedBytes / gb).toFixed(2)),
          diskAvailableGb: Number((availBytes / gb).toFixed(2)),
          diskPercent:
            totalBytes > 0 ? Number(((usedBytes / totalBytes) * 100).toFixed(2)) : 0,
        };
      }
    }
    return {
      diskTotalGb: 0,
      diskUsedGb: 0,
      diskAvailableGb: 0,
      diskPercent: 0,
    };
  }

  public async collect(diskTargetPath = '/'): Promise<HostResourceStats> {
    let cpuPercent = 0;
    const currentCpu = this.readProcStatCpu();
    if (currentCpu && this.prevCpu) {
      const totalDelta = currentCpu.total - this.prevCpu.total;
      const idleDelta = currentCpu.idle - this.prevCpu.idle;
      if (totalDelta > 0) {
        cpuPercent = Number(
          Math.min(100, Math.max(0, ((totalDelta - idleDelta) / totalDelta) * 100)).toFixed(2)
        );
      }
    }
    if (currentCpu) this.prevCpu = currentCpu;

    const cpus = os.cpus();
    const [load1, load5, load15] = os.loadavg();
    const mem = this.readProcMeminfo();
    const disk = await this.readRootDiskUsage(diskTargetPath);

    const now = Date.now();
    const net = this.readProcNetDev();
    let netRxRateBps = 0;
    let netTxRateBps = 0;
    if (this.prevNet && now > this.prevNet.ts) {
      const elapsedSec = (now - this.prevNet.ts) / 1000;
      netRxRateBps = Math.max(0, Math.round((net.rxBytes - this.prevNet.rx) / elapsedSec));
      netTxRateBps = Math.max(0, Math.round((net.txBytes - this.prevNet.tx) / elapsedSec));
    }
    this.prevNet = { rx: net.rxBytes, tx: net.txBytes, ts: now };

    return {
      timestamp: new Date().toISOString(),
      hostname: os.hostname(),
      cpuModel: cpus[0]?.model || 'Linux CPU',
      cpuCores: cpus.length || 1,
      cpuPercent,
      loadAvg1: Number(load1.toFixed(2)),
      loadAvg5: Number(load5.toFixed(2)),
      loadAvg15: Number(load15.toFixed(2)),
      ...mem,
      ...disk,
      netRxBytes: net.rxBytes,
      netTxBytes: net.txBytes,
      netRxRateBps,
      netTxRateBps,
      uptimeSeconds: Math.floor(os.uptime()),
    };
  }
}
