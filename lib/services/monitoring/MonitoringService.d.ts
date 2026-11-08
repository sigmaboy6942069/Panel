import { UnifiedDatabase } from '../../db/database';
import { NodeManager } from '../nodes/NodeClient';
import { InstanceManager } from '../virtualization/InstanceManager';
/**
 * Non-blocking Live & Historical Telemetry Collector, Threshold Alert Engine,
 * In-Panel Notification Manager, and Signed Webhook Dispatcher (Part 13 & Part 16).
 */
export declare class MonitoringService {
    private db;
    private nodeManager;
    private instanceManager;
    private pollTimer;
    private isPolling;
    constructor(db: UnifiedDatabase, nodeManager: NodeManager, instanceManager: InstanceManager);
    startBackgroundLoop(intervalMs?: number): void;
    stopBackgroundLoop(): void;
    collectCycle(): Promise<void>;
    getMetricsHistory(targetType: 'node' | 'kvm' | 'lxc', targetId: number, hours?: number): Promise<any[]>;
    private evaluateAlertRules;
    createNotification(input: {
        userId: number;
        type?: 'info' | 'success' | 'warning' | 'critical';
        title: string;
        message: string;
        data?: Record<string, unknown>;
    }): Promise<number>;
    listUserNotifications(userId: number, unreadOnly?: boolean): Promise<any[]>;
    markNotificationsRead(userId: number, notificationId?: number): Promise<void>;
    dispatchWebhookEvent(eventType: string, payload: Record<string, unknown>): Promise<void>;
    private postWebhookNonBlocking;
}
