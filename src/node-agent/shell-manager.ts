import fs from 'fs';
import * as pty from 'node-pty';
import WebSocket from 'ws';
import { runAllowlistedCommand } from './command-runner';

export interface HostDiagnosticResult {
  preset: string;
  description: string;
  command: string;
  exitCode: number;
  durationMs: number;
  output: string;
  executedAt: string;
}

/**
 * Restricted, audited Admin Node Console & Diagnostic Shell Manager.
 *
 * Security model (Part 12 & Part 22):
 * 1. Safe Preset Diagnostic Mode is ALWAYS available to super-admins (`lxc-ls`, `df`, `free`, `uptime`, `ip addr`, `ps`, `lxc-checkconfig`) with zero arbitrary shell execution.
 * 2. Interactive `node-pty` Host Shell requires BOTH `admin` role AND explicit opt-in (`HKVM_ENABLE_NODE_SHELL=true`), and logs every session lifecycle + input line for auditability.
 */
export class AdminNodeShellManager {
  private interactiveEnabled: boolean;
  private onAuditEvent?: (event: {
    action: string;
    actor: string;
    details: Record<string, unknown>;
  }) => void;

  constructor(options?: {
    interactiveEnabled?: boolean;
    onAuditEvent?: (event: {
      action: string;
      actor: string;
      details: Record<string, unknown>;
    }) => void;
  }) {
    this.interactiveEnabled =
      options?.interactiveEnabled ??
      (process.env.TGVPANEL_ENABLE_NODE_SHELL === 'true' ||
        process.env.HKVM_ENABLE_NODE_SHELL === 'true');
    this.onAuditEvent = options?.onAuditEvent;
  }

  public isInteractiveShellEnabled(): boolean {
    return this.interactiveEnabled;
  }

  public async runDiagnosticPreset(
    preset: string,
    actor = 'admin'
  ): Promise<HostDiagnosticResult> {
    const presets: Record<
      string,
      { bin: string; args: string[]; description: string; asRoot?: boolean }
    > = {
      uptime: { bin: 'uptime', args: [], description: 'Host uptime and load averages' },
      uname: { bin: 'uname', args: ['-a'], description: 'Kernel and architecture version' },
      memory: { bin: 'free', args: ['-h'], description: 'Host RAM and swap allocation' },
      disk: { bin: 'df', args: ['-hT'], description: 'Mounted filesystems and disk usage' },
      processes: { bin: 'ps', args: ['aux', '--sort=-%mem'], description: 'Top host processes by memory' },
      network_links: { bin: 'ip', args: ['-br', 'addr'], description: 'Network interfaces and IP addresses' },
      network_routes: { bin: 'ip', args: ['route'], description: 'Kernel IPv4 routing table' },
      bridges: { bin: 'ip', args: ['link', 'show', 'type', 'bridge'], description: 'Linux network bridges' },
      iptables_nat: { bin: 'iptables', args: ['-t', 'nat', '-S'], description: 'Host NAT & MASQUERADE rules', asRoot: true },
      sysctl_net: { bin: 'sysctl', args: ['net.ipv4.ip_forward'], description: 'Kernel IPv4 packet forwarding state' },
      lxc_list: { bin: 'lxc-ls', args: ['-f'], description: 'LXC containers runtime summary', asRoot: true },
      lxc_checkconfig: { bin: 'lxc-checkconfig', args: [], description: 'Kernel LXC namespace/cgroup support' },
      qemu_version: { bin: 'qemu-system-x86_64', args: ['--version'], description: 'QEMU hypervisor version' },
    };

    const chosen = presets[preset];
    if (!chosen) {
      throw new Error(
        `Unknown diagnostic preset "${preset}". Allowed presets: ${Object.keys(presets).join(', ')}`
      );
    }

    const res = await runAllowlistedCommand(chosen.bin, chosen.args, {
      timeoutMs: 15_000,
      asRoot: chosen.asRoot,
    });
    this.onAuditEvent?.({
      action: 'node_diagnostic_executed',
      actor,
      details: { preset, exitCode: res.exitCode },
    });

    const combined = [res.stdout?.trimEnd(), res.stderr?.trimEnd()].filter(Boolean).join('\n');

    return {
      preset,
      description: chosen.description,
      command: [chosen.bin, ...chosen.args].join(' '),
      exitCode: res.exitCode,
      durationMs: res.durationMs,
      output: (combined || '(Command completed with no output)').slice(0, 64_000),
      executedAt: new Date().toISOString(),
    };
  }

  public attachInteractiveHostPty(
    ws: WebSocket,
    actor: string,
    options: { cols?: number; rows?: number } = {}
  ): void {
    if (!this.interactiveEnabled) {
      ws.send(
        JSON.stringify({
          type: 'error',
          message:
            'Interactive host shell is disabled by security policy (set HKVM_ENABLE_NODE_SHELL=true to enable). Use Safe Diagnostic Presets instead.',
        })
      );
      ws.close(1008, 'Host shell disabled by policy');
      return;
    }

    const shellBin = fs.existsSync('/bin/bash') ? '/bin/bash' : '/bin/sh';
    const cols = Math.min(400, Math.max(20, Number(options.cols || 100)));
    const rows = Math.min(200, Math.max(10, Number(options.rows || 30)));

    this.onAuditEvent?.({
      action: 'node_interactive_shell_opened',
      actor,
      details: { shellBin, cols, rows },
    });

    const term = pty.spawn(shellBin, ['-l'], {
      name: 'xterm-256color',
      cols,
      rows,
      cwd: process.cwd(),
      env: {
        TERM: 'xterm-256color',
        PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
        LANG: 'C.UTF-8',
      },
    });

    let lineBuffer = '';
    let closed = false;

    const closePty = () => {
      if (closed) return;
      closed = true;
      try {
        term.kill();
      } catch {
        // ignore
      }
      this.onAuditEvent?.({
        action: 'node_interactive_shell_closed',
        actor,
        details: {},
      });
    };

    term.onData((data) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'output', data }));
      }
    });

    term.onExit(({ exitCode }) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'exit', exitCode }));
        ws.close();
      }
      closePty();
    });

    ws.on('message', (raw) => {
      const text = raw.toString();
      try {
        const msg = JSON.parse(text);
        if (msg?.type === 'resize') {
          term.resize(
            Math.min(400, Math.max(20, Number(msg.cols || 100))),
            Math.min(200, Math.max(10, Number(msg.rows || 30)))
          );
          return;
        }
        if (msg?.type === 'input' && typeof msg.data === 'string') {
          this.captureCommandAudit(actor, msg.data, (buf) => (lineBuffer = buf), lineBuffer);
          term.write(msg.data);
          return;
        }
      } catch {
        // fallback
      }
      this.captureCommandAudit(actor, text, (buf) => (lineBuffer = buf), lineBuffer);
      term.write(text);
    });

    ws.on('close', closePty);
    ws.on('error', closePty);
  }

  private captureCommandAudit(
    actor: string,
    chunk: string,
    setBuf: (v: string) => void,
    currentBuf: string
  ) {
    let buf = currentBuf + chunk;
    if (buf.includes('\r') || buf.includes('\n')) {
      const cmdLine = buf.replace(/[\r\n]+/g, ' ').trim();
      if (cmdLine) {
        this.onAuditEvent?.({
          action: 'node_shell_command',
          actor,
          details: { command: cmdLine.slice(0, 500) },
        });
      }
      buf = '';
    } else if (buf.length > 1000) {
      buf = buf.slice(-500);
    }
    setBuf(buf);
  }
}
