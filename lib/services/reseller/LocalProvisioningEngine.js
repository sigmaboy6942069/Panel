"use strict";
/**
 * Own-node ("local") provisioning engine.
 *
 * A provider whose `provider` family is `local` has no upstream reseller API.
 * Instead it sells capacity from nodes this panel controls, and an order is
 * fulfilled by creating a real KVM VM or LXC container through the existing
 * virtualization layer.
 *
 * This class deliberately mirrors the small slice of `ResellerApiClient` that
 * the order pipeline needs (`getAccount`, `listKvmOs`, `orderKvm`), so the rest
 * of `ResellerService` stays engine-agnostic: a plan on a local provider takes
 * the same code path as a plan on a bought API.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.LocalProvisioningEngine = exports.LocalProvisionError = exports.LOCAL_PROVIDER_FAMILY = void 0;
exports.LOCAL_PROVIDER_FAMILY = 'local';
/**
 * A provisioning failure that retrying cannot fix (missing host tooling, bad
 * template, exhausted capacity). Orders hitting this are failed instead of
 * being left queued forever.
 */
class LocalProvisionError extends Error {
    code;
    terminal;
    constructor(message, code = 'local_provision_failed', terminal = true) {
        super(message);
        this.name = 'LocalProvisionError';
        this.code = code;
        this.terminal = terminal;
    }
}
exports.LocalProvisionError = LocalProvisionError;
class LocalProvisioningEngine {
    db;
    virt;
    constructor(db, virt) {
        this.db = db;
        this.virt = virt;
    }
    // ---------------------------------------------------------------------------
    // Discovery
    // ---------------------------------------------------------------------------
    /** Nodes that can be sold: not in maintenance, and reachable. */
    async listSellableNodes() {
        const rows = await this.db.all(`SELECT id, name, is_local, status, health_status, cpu_cores, ram_total_mb,
              disk_total_gb, location, max_instances,
              COALESCE(maintenance_mode, 0) AS maintenance_mode
         FROM nodes
        ORDER BY is_local DESC, id ASC`);
        const out = [];
        for (const r of rows) {
            if (Number(r.maintenance_mode) === 1)
                continue;
            const engines = [];
            // A node advertises what it can run via node_capabilities; fall back to
            // both when that table is empty (fresh install).
            const caps = await this.db.get(`SELECT supports_kvm, supports_lxc, kvm_available, lxc_available
           FROM node_capabilities WHERE node_id = ?`, [r.id]);
            if (caps) {
                if (Number(caps.supports_kvm) === 1 || Number(caps.kvm_available) === 1)
                    engines.push('kvm');
                if (Number(caps.supports_lxc) === 1 || Number(caps.lxc_available) === 1)
                    engines.push('lxc');
            }
            if (!caps) {
                engines.push('lxc');
                if (Number(r.is_local) === 1)
                    engines.push('kvm');
            }
            for (const engine of Array.from(new Set(engines))) {
                out.push({
                    id: Number(r.id),
                    name: String(r.name),
                    engine,
                    cpuCores: Number(r.cpu_cores || 0),
                    ramMb: Number(r.ram_total_mb || 0),
                    diskGb: Number(r.disk_total_gb || 0),
                    isLocal: Number(r.is_local) === 1,
                    status: String(r.health_status || r.status || 'unknown'),
                    location: r.location || null,
                });
            }
        }
        return out;
    }
    /** How much of a node is already committed to sold servers. */
    async committedOnNode(nodeId) {
        const row = await this.db.get(`SELECT COUNT(*) AS count,
              COALESCE(SUM(cores), 0) AS cores,
              COALESCE(SUM(memory_gb), 0) * 1024 AS ram_mb,
              COALESCE(SUM(disk_gb), 0) AS disk_gb
         FROM cloud_servers
        WHERE node_id = ?
          AND (upstream_state IS NULL OR upstream_state NOT IN ('terminated', 'cancelled'))`, [nodeId]);
        return {
            cores: Number(row?.cores || 0),
            ramMb: Number(row?.ram_mb || 0),
            diskGb: Number(row?.disk_gb || 0),
            count: Number(row?.count || 0),
        };
    }
    /**
     * Builds sellable plans from real node capacity.
     *
     * Kept intentionally simple and predictable: for each node we offer a few
     * standard shapes that fit within available resources, rather than trying to
     * model every possible configuration. Admins can still hand-edit prices in
     * the catalogue.
     */
    async discoverCapacity(shapes = [
        { cores: 1, memoryGb: 2, diskGb: 20, label: 'Starter' },
        { cores: 2, memoryGb: 4, diskGb: 40, label: 'Standard' },
        { cores: 4, memoryGb: 8, diskGb: 80, label: 'Performance' },
        { cores: 8, memoryGb: 16, diskGb: 160, label: 'High Core' },
    ]) {
        const nodes = await this.listSellableNodes();
        const plans = [];
        for (const node of nodes) {
            const used = await this.committedOnNode(node.id);
            const freeCores = Math.max(0, node.cpuCores - used.cores);
            const freeRamMb = Math.max(0, node.ramMb - used.ramMb);
            const freeDiskGb = Math.max(0, node.diskGb - used.diskGb);
            for (const shape of shapes) {
                if (node.cpuCores > 0 && freeCores < shape.cores)
                    continue;
                if (node.ramMb > 0 && freeRamMb < shape.memoryGb * 1024)
                    continue;
                if (node.diskGb > 0 && freeDiskGb < shape.diskGb)
                    continue;
                // How many of this shape still fit, considering all three dimensions.
                const byCpu = node.cpuCores > 0 ? Math.floor(freeCores / shape.cores) : Infinity;
                const byRam = node.ramMb > 0 ? Math.floor(freeRamMb / (shape.memoryGb * 1024)) : Infinity;
                const byDisk = node.diskGb > 0 ? Math.floor(freeDiskGb / shape.diskGb) : Infinity;
                const available = Math.min(byCpu, byRam, byDisk);
                if (!Number.isFinite(available) || available <= 0)
                    continue;
                plans.push({
                    upstreamPlanId: `node${node.id}-${node.engine}-${shape.cores}c-${shape.memoryGb}g-${shape.diskGb}g`,
                    engine: node.engine,
                    nodeId: node.id,
                    nodeName: node.name,
                    cores: shape.cores,
                    memoryGb: shape.memoryGb,
                    diskGb: shape.diskGb,
                    displayName: `${node.name} ${shape.label || ''} — ${shape.cores} vCPU / ${shape.memoryGb} GB${node.engine === 'kvm' ? ' KVM' : ' LXC'}`.replace(/\s+/g, ' ').trim(),
                    cpuLabel: node.engine === 'kvm' ? 'Dedicated KVM vCPU' : 'LXC Container',
                    family: node.engine === 'kvm' ? 'kvm' : 'lxc',
                    available,
                });
            }
        }
        return plans;
    }
    /** OS images sellable on local nodes. Mirrors the upstream shape. */
    /**
     * Every image this provider can actually deploy, across both engines: LXC
     * container templates plus KVM disk images. A single own-node provider may
     * sell both, so the catalogue has to offer both.
     */
    async listAllOsImages() {
        const [lxc, kvm] = await Promise.all([this.listOsImages('lxc'), this.listOsImages('kvm')]);
        const seen = new Set();
        const out = [];
        for (const image of [...(lxc || []), ...(kvm || [])]) {
            const id = String(image.id || '');
            if (!id || seen.has(id))
                continue;
            seen.add(id);
            out.push(image);
        }
        return out;
    }
    async listOsImages(engine) {
        const want = engine || 'lxc';
        if (want === 'lxc') {
            const rows = await this.db.all(`SELECT slug, template_key, label, name, distro, release, family, arch
           FROM lxc_templates
          WHERE COALESCE(enabled, is_active, 1) = 1
          ORDER BY family, distro, release`);
            if (rows.length) {
                return rows.map((r) => ({
                    id: String(r.slug || r.template_key || `${r.distro}:${r.release}`),
                    name: String(r.label || r.name || '').trim() ||
                        `${this.titleCase(String(r.distro || 'linux'))} ${r.release || ''}`.trim(),
                    family: String(r.family || r.distro || 'linux'),
                    arch: String(r.arch || 'amd64'),
                }));
            }
            // Fall back to the built-in LXC catalogue so a fresh panel still sells.
            return ['ubuntu:24.04', 'ubuntu:22.04', 'debian:12', 'debian:11', 'almalinux:9'].map((id) => {
                const [distro, release] = id.split(':');
                return {
                    id,
                    name: `${this.titleCase(distro)} ${release}`,
                    family: distro,
                    arch: 'amd64',
                };
            });
        }
        const rows = await this.db.all(`SELECT template_key, template_name, template_type, description
         FROM os_templates
        WHERE COALESCE(is_active, 1) = 1
        ORDER BY template_name`);
        const fromDb = rows.map((r) => ({
            id: String(r.template_key),
            name: String(r.template_name || r.template_key),
            family: String(r.template_type || 'linux'),
            arch: 'amd64',
        }));
        // Built-in images shipped with the panel (app.js `OS_TEMPLATES`).
        const builtIn = this.kvmTemplateHook ? this.kvmTemplateHook() : [];
        const seen = new Set(fromDb.map((t) => t.id));
        const merged = [...fromDb];
        for (const t of builtIn || []) {
            if (!t || !t.id || seen.has(t.id))
                continue;
            seen.add(t.id);
            merged.push({ id: t.id, name: t.name, family: t.family, arch: t.arch });
        }
        return merged;
    }
    titleCase(s) {
        return s ? s.charAt(0).toUpperCase() + s.slice(1) : s;
    }
    /** Account/health card for a local provider — no upstream balance exists. */
    async getAccountCard() {
        const nodes = await this.listSellableNodes();
        const capacity = await this.discoverCapacity();
        const cores = nodes.reduce((a, n) => a + n.cpuCores, 0);
        const ramMb = nodes.reduce((a, n) => a + n.ramMb, 0);
        return {
            userId: 0,
            username: 'own-nodes',
            email: null,
            tier: `own-nodes:${nodes.length} node(s)`,
            balance: null,
            chargeEnabled: true,
            resellerOnly: false,
            note: `${nodes.length} sellable node(s), ${cores} vCPU, ${Math.round(ramMb / 1024)} GB RAM, ${capacity.length} sellable shape(s).`,
        };
    }
    // ---------------------------------------------------------------------------
    // Provisioning
    // ---------------------------------------------------------------------------
    /**
     * Fulfils an order by creating a real instance on a node we control.
     * Returns the same shape the upstream client returns, so the caller's
     * existing bookkeeping (cloud_servers, wallet, notifications) is reused.
     */
    async proviseLocalOrder(req) {
        const engine = this.normaliseEngine(req.engine);
        const nodeId = await this.resolveNodeId(engine, req.nodeId ?? null);
        const durationDays = Math.max(0, Math.floor(Number(req.durationDays || 0)));
        if (engine === 'lxc') {
            return this.provisionLxc(req, nodeId, durationDays);
        }
        return this.provisionKvm(req, nodeId, durationDays);
    }
    normaliseEngine(value) {
        const v = String(value || '').trim().toLowerCase();
        if (v === 'kvm')
            return 'kvm';
        return 'lxc';
    }
    /** Picks the target node: explicit, else the least-loaded sellable one. */
    async resolveNodeId(engine, preferred) {
        const nodes = (await this.listSellableNodes()).filter((n) => n.engine === engine);
        if (!nodes.length) {
            throw new Error(`No sellable ${engine.toUpperCase()} node is available. Add or enable a node before selling this plan.`);
        }
        if (preferred) {
            const match = nodes.find((n) => n.id === preferred);
            if (!match) {
                throw new Error(`Node #${preferred} is not available for ${engine.toUpperCase()}.`);
            }
            return match.id;
        }
        let best = nodes[0];
        let bestLoad = Infinity;
        for (const n of nodes) {
            const used = await this.committedOnNode(n.id);
            const load = n.cpuCores > 0 ? used.cores / n.cpuCores : used.count;
            if (load < bestLoad) {
                bestLoad = load;
                best = n;
            }
        }
        return best.id;
    }
    safeContainerName(userId, orderRef) {
        const ref = String(orderRef || '')
            .toLowerCase()
            .replace(/[^a-z0-9]+/g, '-')
            .replace(/^-+|-+$/g, '')
            .slice(-24);
        const name = `c${userId}-${ref || Date.now().toString(36)}`;
        // LXC names are capped and must start with a letter.
        return name.slice(0, 60);
    }
    async provisionLxc(req, nodeId, durationDays) {
        const osId = String(req.osId || 'ubuntu:24.04');
        const [maybeDistro, maybeRelease] = osId.includes(':') ? osId.split(':') : [osId, ''];
        const distro = String(req.distro || maybeDistro || 'ubuntu');
        const release = String(req.release || maybeRelease || '24.04');
        const containerName = this.safeContainerName(req.userId, req.orderRef);
        const input = {
            userId: req.userId,
            nodeId,
            containerName,
            hostname: containerName,
            templateSlug: req.lxcTemplate || `${distro}:${release}`,
            distro,
            release,
            cpuCores: Math.max(1, Math.floor(req.cores || 1)),
            ramMb: Math.max(128, Math.floor((req.memoryGb || 1) * 1024)),
            diskGb: Math.max(2, Math.floor(req.diskGb || 10)),
            bridge: req.bridge || undefined,
            expirationDays: durationDays,
            autostart: true,
            nesting: true,
            // A sold VPS must actually be created on the host.
            provisionOnHost: true,
        };
        let created;
        try {
            created = await this.virt.lxc.createLxcInstance(input);
        }
        catch (err) {
            const msg = err instanceof Error ? err.message : String(err);
            // Host-level problems will not fix themselves on a retry.
            const terminal = /not installed|not available|command not found|ENOENT|no such file/i.test(msg) ||
                /maintenance|capacity|max_instances/i.test(msg);
            throw new LocalProvisionError(msg, 'lxc_provision_failed', terminal);
        }
        const instance = created.instance;
        return this.toOrderResult({
            engine: 'lxc',
            instance,
            nodeId,
            cores: input.cpuCores,
            memoryGb: Math.round(input.ramMb / 1024),
            diskGb: input.diskGb,
            osId,
            osLabel: `${this.titleCase(distro)} ${release}`,
            rootPassword: created.generatedRootPassword,
            warning: created.warning,
        });
    }
    /**
     * KVM creation goes through the legacy `vms` pipeline in `app.js`, which is
     * where the qcow2/cloud-init/ISO orchestration lives. It is injected as a
     * hook so this service stays free of `app.js` internals.
     */
    async provisionKvm(req, nodeId, durationDays) {
        if (!this.kvmCreateHook) {
            throw new LocalProvisionError('KVM provisioning is not wired up. Enable own-node KVM selling by starting the panel normally (the hook is registered at boot).', 'kvm_hook_missing', true);
        }
        const vmName = this.safeContainerName(req.userId, req.orderRef);
        let created;
        try {
            created = await this.kvmCreateHook({
                userId: req.userId,
                nodeId,
                name: vmName,
                cores: Math.max(1, Math.floor(req.cores || 1)),
                memoryMb: Math.max(256, Math.floor((req.memoryGb || 1) * 1024)),
                diskGb: Math.max(5, Math.floor(req.diskGb || 20)),
                templateKey: req.osId || null,
                templateLabel: req.osLabel || null,
                expirationDays: durationDays,
            });
        }
        catch (err) {
            const msg = err instanceof Error ? err.message : String(err);
            const terminal = /unknown os template|not found|not installed|command not found|ENOENT|no such file/i.test(msg);
            throw new LocalProvisionError(msg, 'kvm_provision_failed', terminal);
        }
        return this.toOrderResult({
            engine: 'kvm',
            instance: created.instance,
            nodeId,
            cores: Number(req.cores || 1),
            memoryGb: Number(req.memoryGb || 1),
            diskGb: Number(req.diskGb || 20),
            osId: String(req.osId || ''),
            osLabel: String(req.osLabel || req.osId || 'KVM Guest'),
            rootPassword: created.rootPassword,
            warning: created.warning,
        });
    }
    /** Hook registered from `app.js` at boot (see `src/context.ts`). */
    kvmCreateHook = null;
    setKvmCreateHook(hook) {
        this.kvmCreateHook = hook;
    }
    /**
     * Hook supplying the KVM templates the panel can actually deploy. The
     * built-in catalogue lives in `app.js`, so it is injected rather than
     * duplicated here; without it we fall back to the database table only.
     */
    kvmTemplateHook = null;
    setKvmTemplateHook(hook) {
        this.kvmTemplateHook = hook;
    }
    toOrderResult(args) {
        const ip = args.instance.primaryIp ||
            args.instance.primary_ip ||
            null;
        return {
            id: args.instance.uid || `${args.engine}:${args.instance.refId}`,
            state: args.instance.status || 'running',
            name: args.instance.name,
            os: args.osLabel,
            primaryIpv4: ip,
            primaryIpv6: null,
            expireAt: null,
            credentials: args.rootPassword
                ? { username: args.engine === 'lxc' ? 'root' : 'ubuntu', password: args.rootPassword }
                : null,
            pricing: null,
            note: `Provisioned on own node #${args.nodeId} (${args.engine.toUpperCase()}), ` +
                `${args.cores} vCPU / ${args.memoryGb} GB / ${args.diskGb} GB.` +
                (args.warning ? ` ${args.warning}` : ''),
            // Not part of the upstream payload shape; carried so the caller can link
            // the sold server back to the real KVM/LXC record.
            localInstance: {
                engine: args.engine,
                nodeId: args.nodeId,
                refId: args.instance.refId,
                uid: `${args.engine}:${args.instance.refId}`,
                primaryIp: ip,
            },
        };
    }
    // ---------------------------------------------------------------------------
    // Lifecycle for servers already sold
    // ---------------------------------------------------------------------------
    /** Power actions for an own-node server, given its stored engine + ref. */
    async powerAction(engine, refId, action) {
        const adapter = this.virt.getAdapter(engine);
        return adapter.performLifecycleAction(refId, action);
    }
    /** Live detail for an own-node server. */
    async describeInstance(engine, refId) {
        const adapter = this.virt.getAdapter(engine);
        const instance = await adapter.getInstance(refId);
        const ip = instance?.primaryIp || null;
        return {
            instance,
            detail: {
                id: instance ? String(instance.uid || refId) : String(refId),
                name: instance?.name || `instance-${refId}`,
                state: instance?.status || 'unknown',
                primaryIpv4: ip,
                primaryIpv6: null,
                cpuCores: instance?.cpuCores ?? null,
                memoryMb: instance?.ramMb ?? null,
                diskGb: instance?.diskGb ?? null,
            },
        };
    }
    /** Static catalogue used when an admin syncs a local provider. */
    async listPlansForSync() {
        const capacity = await this.discoverCapacity();
        return capacity.map((c) => ({
            id: c.upstreamPlanId,
            name: c.displayName,
            cpu: c.family,
            cpuLabel: c.cpuLabel,
            cores: c.cores,
            memory: c.memoryGb,
            disk: c.diskGb,
            price: null,
            stock: c.available,
            // Persisted onto reseller_plans by syncCatalogue so an order knows how to
            // fulfil itself.
            engine: c.engine,
            nodeId: c.nodeId,
            lxcTemplate: c.engine === 'lxc' ? `${c.family === 'kvm' ? 'ubuntu' : 'ubuntu'}:24.04` : null,
            bridge: null,
            // A local shape is only "available" while capacity remains.
            available: c.available > 0,
        }));
    }
    /** True when this provider row represents own hardware. */
    static isLocalProvider(provider) {
        return String(provider?.provider || '').trim().toLowerCase() === exports.LOCAL_PROVIDER_FAMILY;
    }
}
exports.LocalProvisioningEngine = LocalProvisioningEngine;
