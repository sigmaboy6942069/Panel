import path from 'path';
import * as pty from 'node-pty';
import WebSocket from 'ws';
import {
  canPasswordlessSudo,
  isBinaryAvailable,
  isRunningAsRoot,
  resolveBinaryPath,
  resolveSudoBinary,
} from './command-runner';
import { SafeValidators } from '../security/middleware';

export interface ActiveConsoleSession {
  sessionId: string;
  containerName: string;
  startedAt: number;
  cols: number;
  rows: number;
  close: () => void;
}

const DEFAULT_LXC_BASE =
  process.env.TGVPANEL_LXC_PATH ||
  process.env.TGVPANEL_LXC_DIR ||
  process.env.HKVM_LXC_PATH ||
  '/var/lib/lxc';

/**
 * Spawns a real interactive PTY attached to an LXC container (`lxc-attach -P <lxcBaseDir> -n <name> ...`)
 * with automatic `sudo -n` elevation when HKVM runs as a non-root operator user,
 * and bridges stdin/stdout/resize frames over WebSocket. Never fabricates terminal output.
 */
export class LxcContainerConsoleManager {
  private sessions = new Map<string, ActiveConsoleSession>();
  private idleTimeoutMs: number;
  private lxcBaseDir: string;

  constructor(idleTimeoutMs = 30 * 60_000, lxcBaseDir = DEFAULT_LXC_BASE) {
    this.idleTimeoutMs = idleTimeoutMs;
    this.lxcBaseDir = path.resolve(lxcBaseDir);
  }

  public attachWebSocket(
    ws: WebSocket,
    containerName: string,
    options: { cols?: number; rows?: number; sessionId?: string } = {}
  ): ActiveConsoleSession {
    const safeName = SafeValidators.containerName(containerName);

    if (!isBinaryAvailable('lxc-attach')) {
      ws.send(
        JSON.stringify({
          type: 'error',
          message:
            'Real LXC console unavailable: lxc-attach binary is not installed on this node.',
        })
      );
      ws.close(1011, 'lxc-attach unavailable');
      throw new Error('lxc-attach is not installed on this node.');
    }

    const lxcAttachBin = resolveBinaryPath('lxc-attach')!;
    const cols = Math.min(400, Math.max(20, Number(options.cols || 100)));
    const rows = Math.min(200, Math.max(10, Number(options.rows || 30)));
    const sessionId =
      options.sessionId || `lxc-pty-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

    const attachArgs = [
      '-P',
      this.lxcBaseDir,
      '-n',
      safeName,
      '--clear-env',
      '--',
      '/bin/sh',
      '-c',
      'if [ -x /bin/bash ]; then exec /bin/bash -l; else exec /bin/sh -l; fi',
    ];

    const sudoPath = !isRunningAsRoot() && canPasswordlessSudo() ? resolveSudoBinary() : null;
    const ptyExecutable = sudoPath || lxcAttachBin;
    const ptyArgs = sudoPath ? ['-n', '--', lxcAttachBin, ...attachArgs] : attachArgs;

    const term = pty.spawn(ptyExecutable, ptyArgs, {
      name: 'xterm-256color',
      cols,
      rows,
      cwd: '/',
      env: {
        TERM: 'xterm-256color',
        HOME: '/root',
        USER: 'root',
        LOGNAME: 'root',
        PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
        LANG: 'C.UTF-8',
      },
    });

    let closed = false;
    let idleTimer = setTimeout(() => teardown('Idle timeout reached'), this.idleTimeoutMs);

    const resetIdle = () => {
      clearTimeout(idleTimer);
      idleTimer = setTimeout(() => teardown('Idle timeout reached'), this.idleTimeoutMs);
    };

    const teardown = (reason?: string) => {
      if (closed) return;
      closed = true;
      clearTimeout(idleTimer);
      this.sessions.delete(sessionId);
      try {
        term.kill();
      } catch {
        // ignore
      }
      if (ws.readyState === WebSocket.OPEN) {
        if (reason) {
          ws.send(JSON.stringify({ type: 'exit', reason }));
        }
        ws.close();
      }
    };

    term.onData((data: string) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'output', data }));
      }
    });

    term.onExit(({ exitCode }) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'exit', exitCode }));
      }
      teardown();
    });

    ws.on('message', (raw) => {
      resetIdle();
      const text = raw.toString();
      try {
        const msg = JSON.parse(text);
        if (msg && typeof msg === 'object') {
          if (msg.type === 'input' && typeof msg.data === 'string') {
            term.write(msg.data);
            return;
          }
          if (msg.type === 'resize') {
            const newCols = Math.min(400, Math.max(20, Number(msg.cols || 100)));
            const newRows = Math.min(200, Math.max(10, Number(msg.rows || 30)));
            term.resize(newCols, newRows);
            return;
          }
          if (msg.type === 'ping') {
            if (ws.readyState === WebSocket.OPEN) {
              ws.send(JSON.stringify({ type: 'pong', ts: Date.now() }));
            }
            return;
          }
        }
      } catch {
        // Plain text fallback
      }
      term.write(text);
    });

    ws.on('close', () => teardown());
    ws.on('error', () => teardown());

    const session: ActiveConsoleSession = {
      sessionId,
      containerName: safeName,
      startedAt: Date.now(),
      cols,
      rows,
      close: () => teardown('Closed by administrator'),
    };
    this.sessions.set(sessionId, session);
    return session;
  }

  public listActiveSessions(): Array<Omit<ActiveConsoleSession, 'close'>> {
    return Array.from(this.sessions.values()).map(({ close: _c, ...rest }) => rest);
  }
}
