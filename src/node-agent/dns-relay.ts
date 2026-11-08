import dgram from 'dgram';
import dns from 'dns';
import fs from 'fs';
import net from 'net';

export interface ParsedDnsQuestion {
  qname: string;
  qtype: number;
  qclass: number;
  questionEndOffset: number;
}

/**
 * Parses the first DNS question from a wire-format RFC 1035 query buffer.
 */
export function parseDnsQuestion(buf: Buffer): ParsedDnsQuestion | null {
  if (!buf || buf.length < 17) return null;
  const flags = buf.readUInt16BE(2);
  if ((flags & 0x8000) !== 0) return null; // ignore responses
  const qdCount = buf.readUInt16BE(4);
  if (qdCount < 1) return null;

  const labels: string[] = [];
  let offset = 12;
  let safety = 0;

  while (offset < buf.length && safety++ < 64) {
    const len = buf[offset];
    if (len === 0) {
      offset += 1;
      break;
    }
    if ((len & 0xc0) !== 0 || offset + 1 + len > buf.length) {
      return null;
    }
    labels.push(buf.subarray(offset + 1, offset + 1 + len).toString('ascii'));
    offset += 1 + len;
  }

  if (offset + 4 > buf.length) return null;
  const qtype = buf.readUInt16BE(offset);
  const qclass = buf.readUInt16BE(offset + 2);
  const questionEndOffset = offset + 4;

  return {
    qname: labels.join('.'),
    qtype,
    qclass,
    questionEndOffset,
  };
}

function ipv4ToBytes(ip: string): Buffer | null {
  const parts = ip.trim().split('.').map((p) => parseInt(p, 10));
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
    return null;
  }
  return Buffer.from(parts);
}

function ipv6ToBytes(ip: string): Buffer | null {
  if (!net.isIPv6(ip)) return null;
  const halves = ip.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':').filter(Boolean) : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':').filter(Boolean) : [];
  const missing = halves.length === 2 ? 8 - (left.length + right.length) : 0;
  if (missing < 0) return null;
  const groups = [
    ...left,
    ...Array.from({ length: missing }, () => '0'),
    ...right,
  ];
  if (groups.length !== 8) return null;
  const out = Buffer.alloc(16);
  for (let i = 0; i < 8; i++) {
    const val = parseInt(groups[i], 16);
    if (Number.isNaN(val) || val < 0 || val > 0xffff) return null;
    out.writeUInt16BE(val, i * 2);
  }
  return out;
}

function buildDnsHeaderResponse(queryBuf: Buffer, questionEndOffset: number, rcode: number, answers: Buffer[]): Buffer {
  const txId = queryBuf.readUInt16BE(0);
  const reqFlags = queryBuf.readUInt16BE(2);
  const rdBit = reqFlags & 0x0100;
  // QR=1 (0x8000), RD preserved, RA=1 (0x0080), RCODE
  const respFlags = 0x8000 | rdBit | 0x0080 | (rcode & 0x000f);

  const header = Buffer.alloc(12);
  header.writeUInt16BE(txId, 0);
  header.writeUInt16BE(respFlags, 2);
  header.writeUInt16BE(1, 4); // QDCOUNT = 1
  header.writeUInt16BE(answers.length, 6); // ANCOUNT
  header.writeUInt16BE(0, 8); // NSCOUNT
  header.writeUInt16BE(0, 10); // ARCOUNT

  const questionSlice = queryBuf.subarray(12, questionEndOffset);
  return Buffer.concat([header, questionSlice, ...answers]);
}

function buildResourceRecord(qtype: number, rdata: Buffer, ttlSec = 60): Buffer {
  const rr = Buffer.alloc(12 + rdata.length);
  rr.writeUInt16BE(0xc00c, 0); // Name pointer to offset 12 (QNAME)
  rr.writeUInt16BE(qtype, 2);
  rr.writeUInt16BE(1, 4); // CLASS IN
  rr.writeUInt32BE(ttlSec, 6);
  rr.writeUInt16BE(rdata.length, 10);
  rdata.copy(rr, 12);
  return rr;
}

/**
 * Synthesizes a valid RFC 1035 DNS reply using the host OS's native resolver (`getaddrinfo` /
 * Windows WSL2 tunnel / `/etc/hosts` / VPN split-DNS) when raw UDP forwarding fails or times out.
 */
export async function synthesizeDnsFromOsLookup(queryBuf: Buffer): Promise<Buffer | null> {
  const parsed = parseDnsQuestion(queryBuf);
  if (!parsed || parsed.qclass !== 1 || !parsed.qname) return null;

  // A (1) or AAAA (28)
  if (parsed.qtype !== 1 && parsed.qtype !== 28) {
    // Return clean empty NOERROR for unsupported types (e.g. HTTPS/SVCB type 65) so clients don't stall
    return buildDnsHeaderResponse(queryBuf, parsed.questionEndOffset, 0, []);
  }

  const family = parsed.qtype === 28 ? 6 : 4;
  try {
    const records = await dns.promises.lookup(parsed.qname, { family, all: true });
    const answers: Buffer[] = [];
    for (const rec of records.slice(0, 8)) {
      const bytes = family === 6 ? ipv6ToBytes(rec.address) : ipv4ToBytes(rec.address);
      if (bytes) {
        answers.push(buildResourceRecord(parsed.qtype, bytes, 60));
      }
    }
    return buildDnsHeaderResponse(queryBuf, parsed.questionEndOffset, 0, answers);
  } catch (err: any) {
    const code = String(err?.code || '');
    if (family === 6) {
      // If host has no IPv6 connectivity/records, check whether IPv4 exists:
      // returning instant empty NOERROR prevents 5-second AAAA stalls in `apt update`!
      try {
        const v4 = await dns.promises.lookup(parsed.qname, { family: 4, all: true });
        if (v4.length > 0) {
          return buildDnsHeaderResponse(queryBuf, parsed.questionEndOffset, 0, []);
        }
      } catch {
        // fall through to NXDOMAIN/SERVFAIL
      }
    }
    if (code === 'ENOTFOUND' || code === 'ENODATA') {
      return buildDnsHeaderResponse(queryBuf, parsed.questionEndOffset, 3, []); // NXDOMAIN
    }
    return null;
  }
}

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
export class BridgeDnsRelay {
  private udpServer: dgram.Socket | null = null;
  private tcpServer: net.Server | null = null;
  private boundPort = 0;
  private excludedIps = new Set<string>();
  private cachedHostUpstreams: { list: string[]; ts: number } = { list: [], ts: 0 };

  public addExcludedLoopIp(ip: string): void {
    if (ip) this.excludedIps.add(ip.trim());
  }

  public getPort(): number {
    return this.boundPort;
  }

  public isRunning(): boolean {
    return this.boundPort > 0 && this.udpServer !== null;
  }

  private getUpstreamServers(): string[] {
    const now = Date.now();
    if (now - this.cachedHostUpstreams.ts > 15_000 || this.cachedHostUpstreams.list.length === 0) {
      const list: string[] = [];
      const envDns = (process.env.TGVPANEL_LXC_DNS || process.env.HKVM_LXC_DNS || '').trim();
      if (envDns) {
        for (const s of envDns.split(/[\s,]+/)) {
          if (net.isIPv4(s) && !this.excludedIps.has(s) && !list.includes(s)) list.push(s);
        }
      }
      try {
        if (fs.existsSync('/etc/resolv.conf')) {
          const raw = fs.readFileSync('/etc/resolv.conf', 'utf8');
          for (const line of raw.split('\n')) {
            const m = line.trim().match(/^nameserver\s+(\d{1,3}(?:\.\d{1,3}){3})\b/i);
            if (m && net.isIPv4(m[1]) && !this.excludedIps.has(m[1]) && !list.includes(m[1])) {
              list.push(m[1]);
            }
          }
        }
      } catch {
        // ignore
      }
      for (const pub of ['1.1.1.1', '8.8.8.8']) {
        if (!this.excludedIps.has(pub) && !list.includes(pub)) list.push(pub);
      }
      this.cachedHostUpstreams = { list: list.slice(0, 4), ts: now };
    }
    return this.cachedHostUpstreams.list.filter((ip) => !this.excludedIps.has(ip));
  }

  public async resolveDnsPacket(queryBuf: Buffer): Promise<Buffer | null> {
    if (!queryBuf || queryBuf.length < 12) return null;
    const upstreams = this.getUpstreamServers();
    let emptyOrNxReply: Buffer | null = null;

    if (upstreams.length > 0) {
      const udpReply = await this.forwardOverUdp(queryBuf, upstreams, 1350);
      if (udpReply && udpReply.length >= 12) {
        const rcode = udpReply.readUInt16BE(2) & 0x000f;
        const ancount = udpReply.readUInt16BE(6);
        if (rcode === 0 && ancount > 0) {
          return udpReply;
        }
        if (rcode === 0 || rcode === 3) {
          emptyOrNxReply = udpReply;
        }
      }
    }

    // Fallback to OS-level native getaddrinfo (works through WSL2 Hyper-V tunnel, VPNs & /etc/hosts!)
    const synthesized = await synthesizeDnsFromOsLookup(queryBuf);
    if (synthesized && synthesized.length >= 12) {
      const synthAncount = synthesized.readUInt16BE(6);
      if (synthAncount > 0 || !emptyOrNxReply) {
        return synthesized;
      }
    }

    if (emptyOrNxReply) {
      return emptyOrNxReply;
    }

    // Return SERVFAIL if both upstream UDP and OS lookup failed
    const parsed = parseDnsQuestion(queryBuf);
    if (parsed) {
      return buildDnsHeaderResponse(queryBuf, parsed.questionEndOffset, 2, []);
    }
    return null;
  }

  private forwardOverUdp(queryBuf: Buffer, upstreams: string[], timeoutMs: number): Promise<Buffer | null> {
    return new Promise((resolve) => {
      const txId = queryBuf.readUInt16BE(0);
      let settled = false;
      let fallbackReply: Buffer | null = null;
      let responsesSeen = 0;

      const sock = dgram.createSocket('udp4');
      const finish = (buf: Buffer | null) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        try {
          sock.close();
        } catch {
          // ignore
        }
        resolve(buf);
      };

      const timer = setTimeout(() => finish(fallbackReply), timeoutMs);
      timer.unref?.();

      sock.on('error', () => finish(fallbackReply));
      sock.on('message', (msg) => {
        if (msg.length < 12 || msg.readUInt16BE(0) !== txId) return;
        responsesSeen++;
        const rcode = msg.readUInt16BE(2) & 0x000f;
        const ancount = msg.readUInt16BE(6);
        if (rcode === 0 && ancount > 0) {
          finish(msg);
          return;
        }
        if (
          !fallbackReply ||
          (rcode === 0 && (fallbackReply.readUInt16BE(2) & 0x000f) !== 0)
        ) {
          fallbackReply = msg;
        }
        if (responsesSeen >= upstreams.length) {
          finish(fallbackReply);
        }
      });

      for (const ns of upstreams) {
        try {
          sock.send(queryBuf, 53, ns);
        } catch {
          // ignore individual send error
        }
      }
    });
  }

  public async ensureStarted(): Promise<number> {
    if (this.isRunning()) return this.boundPort;

    const preferred =
      parseInt(process.env.TGVPANEL_DNS_RELAY_PORT || process.env.HKVM_DNS_RELAY_PORT || '53539', 10) ||
      53539;
    const candidatePorts = [
      preferred,
      53540,
      53541,
      53542,
      0, // OS-assigned fallback
    ];

    for (const port of candidatePorts) {
      const bound = await this.tryBindPort(port);
      if (bound > 0) {
        this.boundPort = bound;
        return bound;
      }
    }
    return 0;
  }

  private tryBindPort(port: number): Promise<number> {
    return new Promise((resolve) => {
      const udp = dgram.createSocket('udp4');
      let resolved = false;

      const fail = () => {
        if (resolved) return;
        resolved = true;
        try {
          udp.close();
        } catch {
          // ignore
        }
        resolve(0);
      };

      udp.once('error', fail);
      udp.bind(port, '0.0.0.0', () => {
        const addr = udp.address();
        const actualPort = typeof addr === 'object' ? addr.port : port;

        const tcp = net.createServer((socket) => {
          socket.setTimeout(4000, () => socket.destroy());
          let acc: Buffer = Buffer.alloc(0);
          socket.on('data', async (chunk: Buffer | string) => {
            const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
            acc = Buffer.concat([acc, buf]);
            while (acc.length >= 2) {
              const msgLen = acc.readUInt16BE(0);
              if (acc.length < 2 + msgLen) break;
              const query = acc.subarray(2, 2 + msgLen);
              acc = acc.subarray(2 + msgLen);
              const reply = await this.resolveDnsPacket(query);
              if (reply && !socket.destroyed) {
                const lenPrefix = Buffer.alloc(2);
                lenPrefix.writeUInt16BE(reply.length, 0);
                socket.write(Buffer.concat([lenPrefix, reply]));
              }
            }
          });
          socket.on('error', () => socket.destroy());
        });

        tcp.once('error', () => {
          try {
            tcp.close();
          } catch {
            // ignore
          }
          fail();
        });

        tcp.listen(actualPort, '0.0.0.0', () => {
          if (resolved) return;
          resolved = true;

          udp.removeListener('error', fail);
          udp.on('error', () => undefined);
          udp.on('message', async (msg, rinfo) => {
            const reply = await this.resolveDnsPacket(msg);
            if (reply && this.udpServer) {
              try {
                this.udpServer.send(reply, rinfo.port, rinfo.address);
              } catch {
                // ignore
              }
            }
          });

          udp.unref();
          tcp.unref();
          this.udpServer = udp;
          this.tcpServer = tcp;
          resolve(actualPort);
        });
      });
    });
  }

  public stop(): void {
    this.boundPort = 0;
    if (this.udpServer) {
      try {
        this.udpServer.close();
      } catch {
        // ignore
      }
      this.udpServer = null;
    }
    if (this.tcpServer) {
      try {
        this.tcpServer.close();
      } catch {
        // ignore
      }
      this.tcpServer = null;
    }
  }
}

let sharedDnsRelay: BridgeDnsRelay | null = null;
export function getSharedBridgeDnsRelay(): BridgeDnsRelay {
  if (!sharedDnsRelay) {
    sharedDnsRelay = new BridgeDnsRelay();
  }
  return sharedDnsRelay;
}
