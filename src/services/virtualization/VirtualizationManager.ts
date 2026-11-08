import { KVMAdapter } from './KVMAdapter';
import { LXCAdapter } from './LXCAdapter';
import { VirtualizationAdapter, VirtualizationEngine } from './VirtualizationAdapter';

export class VirtualizationManager {
  public readonly kvm: KVMAdapter;
  public readonly lxc: LXCAdapter;
  private adapters: Map<VirtualizationEngine, VirtualizationAdapter>;

  constructor(kvmAdapter: KVMAdapter, lxcAdapter: LXCAdapter) {
    this.kvm = kvmAdapter;
    this.lxc = lxcAdapter;
    this.adapters = new Map<VirtualizationEngine, VirtualizationAdapter>([
      ['kvm', kvmAdapter],
      ['lxc', lxcAdapter],
    ]);
  }

  public getAdapter(engine: VirtualizationEngine): VirtualizationAdapter {
    const adapter = this.adapters.get(engine);
    if (!adapter) {
      throw new Error(`Unsupported virtualization engine: ${engine}`);
    }
    return adapter;
  }

  public getSupportedEngines(): VirtualizationEngine[] {
    return Array.from(this.adapters.keys());
  }

  public parseInstanceUid(uid: string): { engine: VirtualizationEngine; refId: number } {
    const m = String(uid || '').trim().match(/^(kvm|lxc)[:\-](\d+)$/i);
    if (!m) {
      throw new Error(`Invalid instance identifier "${uid}". Expected "kvm:<id>" or "lxc:<id>".`);
    }
    return {
      engine: m[1].toLowerCase() as VirtualizationEngine,
      refId: parseInt(m[2], 10),
    };
  }
}
