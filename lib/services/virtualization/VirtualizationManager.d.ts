import { KVMAdapter } from './KVMAdapter';
import { LXCAdapter } from './LXCAdapter';
import { VirtualizationAdapter, VirtualizationEngine } from './VirtualizationAdapter';
export declare class VirtualizationManager {
    readonly kvm: KVMAdapter;
    readonly lxc: LXCAdapter;
    private adapters;
    constructor(kvmAdapter: KVMAdapter, lxcAdapter: LXCAdapter);
    getAdapter(engine: VirtualizationEngine): VirtualizationAdapter;
    getSupportedEngines(): VirtualizationEngine[];
    parseInstanceUid(uid: string): {
        engine: VirtualizationEngine;
        refId: number;
    };
}
