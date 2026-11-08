"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.MonitoringService = void 0;
const crypto_1 = __importDefault(require("crypto"));
const http_1 = __importDefault(require("http"));
const https_1 = __importDefault(require("https"));
const crypto_vault_1 = require("../../security/crypto-vault");
/**
 * Non-blocking Live & Historical Telemetry Collector, Threshold Alert Engine,
 * In-Panel Notification Manager, and Signed Webhook Dispatcher (Part 13 & Part 16).
 */
class MonitoringService {
    db;
    nodeManager;
    instanceManager;
    pollTimer = null;
    isPolling = false;
    constructor(db, nodeManager, instanceManager) {
        this.db = db;
        this.nodeManager = nodeManager;
        this.instanceManager = instanceManager;
    }
    startBackgroundLoop(intervalMs = 60_000) {
        if (this.pollTimer)
            return;
        // Kick off initial sample shortly after boot without blocking startup
        const bootTimer = setTimeout(() => {
            this.collectCycle().catch(() => undefined);
        }, 3000);
        if (typeof bootTimer.unref === 'function')
            bootTimer.unref();
        this.pollTimer = setInterval(() => {
            this.collectCycle().catch(() => undefined);
        }, intervalMs);
        if (typeof this.pollTimer.unref === 'function')
            this.pollTimer.unref();
    }
    stopBackgroundLoop() {
        if (this.pollTimer) {
            clearInterval(this.pollTimer);
            this.pollTimer = null;
        }
    }
    async collectCycle() {
        if (this.isPolling)
            return;
        this.isPolling = true;
        try {
            const nodes = await this.nodeManager.listNodes();
            for (const n of nodes) {
                try {
                    const { stats } = await this.nodeManager.checkNodeHealthAndStats(n.id);
                    await this.db.run(`INSERT INTO metrics_history
               (target_type, target_id, cpu_percent, ram_used_mb, ram_total_mb, disk_used_gb, disk_total_gb, net_rx_bytes, net_tx_bytes, load_avg_1)
             VALUES ('node', ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
                        n.id,
                        stats.cpuPercent,
                        stats.ramUsedMb,
                        stats.ramTotalMb,
                        stats.diskUsedGb,
                        stats.diskTotalGb,
                        stats.netRxBytes,
                        stats.netTxBytes,
                        stats.loadAvg1,
                    ]);
                    await this.evaluateAlertRules('node', {
                        targetId: n.id,
                        targetName: n.name,
                        cpu_percent: stats.cpuPercent,
                        ram_percent: stats.ramPercent,
                        disk_percent: stats.diskPercent,
                        load_avg: stats.loadAvg1,
                    });
                }
                catch {
                    // Node offline — circuit breaker already updated node status
                    await this.dispatchWebhookEvent('node.offline', {
                        nodeId: n.id,
                        nodeName: n.name,
                        timestamp: new Date().toISOString(),
                    });
                }
            }
            // Check expired LXC instances
            await this.instanceManager.processExpiredInstances().catch(() => undefined);
            // Prune metrics older than 14 days to keep SQLite compact
            await this.db.run(`DELETE FROM metrics_history WHERE datetime(recorded_at) < datetime('now', '-14 days')`);
        }
        finally {
            this.isPolling = false;
        }
    }
    async getMetricsHistory(targetType, targetId, hours = 24) {
        const safeHours = Math.min(336, Math.max(1, Number(hours || 24)));
        return this.db.all(`SELECT cpu_percent, ram_used_mb, ram_total_mb, disk_used_gb, disk_total_gb,
              net_rx_bytes, net_tx_bytes, load_avg_1, recorded_at
       FROM metrics_history
       WHERE target_type = ? AND target_id = ?
         AND datetime(recorded_at) >= datetime('now', ?)
       ORDER BY id ASC
       LIMIT 500`, [targetType, targetId, `-${safeHours} hours`]);
    }
    async evaluateAlertRules(scope, metrics) {
        const rules = await this.db.all(`SELECT * FROM alert_rules WHERE enabled = 1 AND target_scope = ?`, [scope]);
        for (const rule of rules) {
            const val = Number(metrics[rule.metric] ?? 0);
            const threshold = Number(rule.threshold || 90);
            let breached = false;
            if (rule.operator === '>=' && val >= threshold)
                breached = true;
            else if (rule.operator === '>' && val > threshold)
                breached = true;
            else if (rule.operator === '<=' && val <= threshold)
                breached = true;
            if (!breached)
                continue;
            // Respect 15-minute cooldown between identical alerts
            if (rule.last_triggered_at &&
                Date.now() - new Date(rule.last_triggered_at).getTime() < 15 * 60_000) {
                continue;
            }
            await this.db.run(`UPDATE alert_rules SET last_triggered_at = datetime('now') WHERE id = ?`, [rule.id]);
            const admins = await this.db.all(`SELECT id FROM users WHERE role = 'admin'`);
            for (const adm of admins) {
                await this.createNotification({
                    userId: adm.id,
                    type: rule.severity || 'warning',
                    title: `Alert: ${rule.name} (${metrics.targetName})`,
                    message: `${rule.metric} reached ${val}% (threshold ${rule.operator} ${threshold}%) on ${scope} "${metrics.targetName}".`,
                });
            }
            await this.dispatchWebhookEvent('alert.triggered', {
                ruleName: rule.name,
                scope,
                targetName: metrics.targetName,
                metric: rule.metric,
                value: val,
                threshold,
            });
        }
    }
    // --- Notifications ---
    async createNotification(input) {
        const ins = await this.db.run(`INSERT INTO notifications (user_id, type, title, message, data)
       VALUES (?, ?, ?, ?, ?)`, [
            input.userId,
            input.type || 'info',
            input.title,
            input.message,
            input.data ? JSON.stringify(input.data) : null,
        ]);
        return ins.lastID;
    }
    async listUserNotifications(userId, unreadOnly = false) {
        const sql = unreadOnly
            ? `SELECT * FROM notifications WHERE user_id = ? AND is_read = 0 ORDER BY id DESC LIMIT 100`
            : `SELECT * FROM notifications WHERE user_id = ? ORDER BY id DESC LIMIT 100`;
        return this.db.all(sql, [userId]);
    }
    async markNotificationsRead(userId, notificationId) {
        if (notificationId) {
            await this.db.run(`UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?`, [notificationId, userId]);
        }
        else {
            await this.db.run(`UPDATE notifications SET is_read = 1 WHERE user_id = ?`, [userId]);
        }
    }
    // --- Outbound HMAC Webhooks ---
    async dispatchWebhookEvent(eventType, payload) {
        const hooks = await this.db.all(`SELECT * FROM webhooks WHERE is_active = 1`);
        for (const h of hooks) {
            let subscribed = [];
            try {
                subscribed = JSON.parse(h.events || '[]');
            }
            catch {
                subscribed = [];
            }
            if (!subscribed.includes('*') && !subscribed.includes(eventType))
                continue;
            const bodyStr = JSON.stringify({
                event: eventType,
                timestamp: new Date().toISOString(),
                data: payload,
            });
            const secret = h.secret_enc ? (0, crypto_vault_1.decryptSecret)(h.secret_enc) : '';
            const signature = secret
                ? crypto_1.default.createHmac('sha256', secret).update(bodyStr).digest('hex')
                : '';
            this.postWebhookNonBlocking(h.id, h.url, bodyStr, signature).catch(() => undefined);
        }
    }
    postWebhookNonBlocking(hookId, urlStr, bodyStr, signatureHex) {
        return new Promise((resolve) => {
            try {
                const u = new URL(urlStr);
                const isHttps = u.protocol === 'https:';
                const mod = isHttps ? https_1.default : http_1.default;
                const req = mod.request({
                    method: 'POST',
                    hostname: u.hostname,
                    port: u.port || (isHttps ? 443 : 80),
                    path: u.pathname + u.search,
                    timeout: 8000,
                    headers: {
                        'Content-Type': 'application/json',
                        'Content-Length': Buffer.byteLength(bodyStr),
                        'User-Agent': 'TGVPANEL-Webhook/3.0',
                        ...(signatureHex ? { 'X-HKVM-Signature-256': `sha256=${signatureHex}` } : {}),
                    },
                }, (res) => {
                    res.resume();
                    this.db
                        .run(`UPDATE webhooks SET last_triggered_at = datetime('now'), last_status_code = ? WHERE id = ?`, [res.statusCode || 0, hookId])
                        .finally(() => resolve());
                });
                req.on('error', () => resolve());
                req.on('timeout', () => {
                    req.destroy();
                    resolve();
                });
                req.write(bodyStr);
                req.end();
            }
            catch {
                resolve();
            }
        });
    }
}
exports.MonitoringService = MonitoringService;
