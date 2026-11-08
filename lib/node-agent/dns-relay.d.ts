export interface ParsedDnsQuestion {
    qname: string;
    qtype: number;
    qclass: number;
    questionEndOffset: number;
}
/**
 * Parses the first DNS question from a wire-format RFC 1035 query buffer.
 */
export declare function parseDnsQuestion(buf: Buffer): ParsedDnsQuestion | null;
/**
 * Synthesizes a valid RFC 1035 DNS reply using the host OS's native resolver (`getaddrinfo` /
 * Windows WSL2 tunnel / `/etc/hosts` / VPN split-DNS) when raw UDP forwarding fails or times out.
 */
export declare function synthesizeDnsFromOsLookup(queryBuf: Buffer): Promise<Buffer | null>;
/**
 * Host-side UDP + TCP DNS Relay for LXC bridges (`lxcbr0`).
 *
 * Why this is essential on WSL2, Ubuntu (`systemd-resolved`), Docker, and restricted ISP/VPN hosts:
 * - Containers in an isolated network namespace cannot reach host loopback resolvers (`127.0.0.53`
 *   on Ubuntu or `10.255.255.254` on WSL2 `dnsTunneling`), and many Wi-Fi/ISP/hotspot networks block
 *   direct external UDP:53 (`1.1.1.1`) from nested NAT subnets.
 * - By listening on the host and intercepting `<bridgeIp>:53` (via `PREROUTING REDIRECT`), this relay
 *   forwards container DNS queries through the host's own working resolvers (`10.255.255.254`,
 *   `127.0.0.53`, `172.x.x.1`, LAN DNS, `1.1.1.1`, `8.8.8.8`) with an automatic OS `getaddrinfo`
 *   fallback (`dns.promises.lookup`).
 */
export declare class BridgeDnsRelay {
    private udpServer;
    private tcpServer;
    private boundPort;
    private excludedIps;
    private cachedHostUpstreams;
    addExcludedLoopIp(ip: string): void;
    getPort(): number;
    isRunning(): boolean;
    private getUpstreamServers;
    resolveDnsPacket(queryBuf: Buffer): Promise<Buffer | null>;
    private forwardOverUdp;
    ensureStarted(): Promise<number>;
    private tryBindPort;
    stop(): void;
}
export declare function getSharedBridgeDnsRelay(): BridgeDnsRelay;
