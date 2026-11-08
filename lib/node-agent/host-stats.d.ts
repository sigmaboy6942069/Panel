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
export declare class HostStatsCollector {
    private prevCpu;
    private prevNet;
    constructor();
    private readProcStatCpu;
    private readProcMeminfo;
    private readProcNetDev;
    private readRootDiskUsage;
    collect(diskTargetPath?: string): Promise<HostResourceStats>;
}
