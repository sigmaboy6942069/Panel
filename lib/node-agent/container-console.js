"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.LxcContainerConsoleManager = void 0;
const path_1 = __importDefault(require("path"));
const pty = __importStar(require("node-pty"));
const ws_1 = __importDefault(require("ws"));
const command_runner_1 = require("./command-runner");
const middleware_1 = require("../security/middleware");
const DEFAULT_LXC_BASE = process.env.TGVPANEL_LXC_PATH ||
    process.env.TGVPANEL_LXC_DIR ||
    process.env.HKVM_LXC_PATH ||
    '/var/lib/lxc';
/**
 * Spawns a real interactive PTY attached to an LXC container (`lxc-attach -P <lxcBaseDir> -n <name> ...`)
 * with automatic `sudo -n` elevation when HKVM runs as a non-root operator user,
 * and bridges stdin/stdout/resize frames over WebSocket. Never fabricates terminal output.
 */
class LxcContainerConsoleManager {
    sessions = new Map();
    idleTimeoutMs;
    lxcBaseDir;
    constructor(idleTimeoutMs = 30 * 60_000, lxcBaseDir = DEFAULT_LXC_BASE) {
        this.idleTimeoutMs = idleTimeoutMs;
        this.lxcBaseDir = path_1.default.resolve(lxcBaseDir);
    }
    attachWebSocket(ws, containerName, options = {}) {
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        if (!(0, command_runner_1.isBinaryAvailable)('lxc-attach')) {
            ws.send(JSON.stringify({
                type: 'error',
                message: 'Real LXC console unavailable: lxc-attach binary is not installed on this node.',
            }));
            ws.close(1011, 'lxc-attach unavailable');
            throw new Error('lxc-attach is not installed on this node.');
        }
        const lxcAttachBin = (0, command_runner_1.resolveBinaryPath)('lxc-attach');
        const cols = Math.min(400, Math.max(20, Number(options.cols || 100)));
        const rows = Math.min(200, Math.max(10, Number(options.rows || 30)));
        const sessionId = options.sessionId || `lxc-pty-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
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
        const sudoPath = !(0, command_runner_1.isRunningAsRoot)() && (0, command_runner_1.canPasswordlessSudo)() ? (0, command_runner_1.resolveSudoBinary)() : null;
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
        const teardown = (reason) => {
            if (closed)
                return;
            closed = true;
            clearTimeout(idleTimer);
            this.sessions.delete(sessionId);
            try {
                term.kill();
            }
            catch {
                // ignore
            }
            if (ws.readyState === ws_1.default.OPEN) {
                if (reason) {
                    ws.send(JSON.stringify({ type: 'exit', reason }));
                }
                ws.close();
            }
        };
        term.onData((data) => {
            if (ws.readyState === ws_1.default.OPEN) {
                ws.send(JSON.stringify({ type: 'output', data }));
            }
        });
        term.onExit(({ exitCode }) => {
            if (ws.readyState === ws_1.default.OPEN) {
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
                        if (ws.readyState === ws_1.default.OPEN) {
                            ws.send(JSON.stringify({ type: 'pong', ts: Date.now() }));
                        }
                        return;
                    }
                }
            }
            catch {
                // Plain text fallback
            }
            term.write(text);
        });
        ws.on('close', () => teardown());
        ws.on('error', () => teardown());
        const session = {
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
    listActiveSessions() {
        return Array.from(this.sessions.values()).map(({ close: _c, ...rest }) => rest);
    }
}
exports.LxcContainerConsoleManager = LxcContainerConsoleManager;
