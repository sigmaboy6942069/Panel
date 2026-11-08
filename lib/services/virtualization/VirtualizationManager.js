"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.VirtualizationManager = void 0;
class VirtualizationManager {
    kvm;
    lxc;
    adapters;
    constructor(kvmAdapter, lxcAdapter) {
        this.kvm = kvmAdapter;
        this.lxc = lxcAdapter;
        this.adapters = new Map([
            ['kvm', kvmAdapter],
            ['lxc', lxcAdapter],
        ]);
    }
    getAdapter(engine) {
        const adapter = this.adapters.get(engine);
        if (!adapter) {
            throw new Error(`Unsupported virtualization engine: ${engine}`);
        }
        return adapter;
    }
    getSupportedEngines() {
        return Array.from(this.adapters.keys());
    }
    parseInstanceUid(uid) {
        const m = String(uid || '').trim().match(/^(kvm|lxc)[:\-](\d+)$/i);
        if (!m) {
            throw new Error(`Invalid instance identifier "${uid}". Expected "kvm:<id>" or "lxc:<id>".`);
        }
        return {
            engine: m[1].toLowerCase(),
            refId: parseInt(m[2], 10),
        };
    }
}
exports.VirtualizationManager = VirtualizationManager;
