/**
 * End-to-end: sell a VPS from our OWN node.
 * Real ResellerService + real LXCAdapter + real migrations.
 * Only the host provisioning call is stubbed (no LXC in sandbox).
 */
const path = require('path');
const fs = require('fs');
const { DatabaseSync } = require('node:sqlite');
const repo = '/home/user/Panel';

class ShimDb {
  constructor(f){this.raw=new DatabaseSync(f);}
  close(cb){this.raw.close();cb&&cb(null);}
  exec(sql,cb){try{this.raw.exec(sql);cb&&cb(null);}catch(e){cb?cb(e):console.error(e);}}
  run(sql,p,cb){if(typeof p==='function'){cb=p;p=[];}try{const r=this.raw.prepare(sql).run(...(p||[]));cb&&cb.call({lastID:Number(r.lastInsertRowid),changes:Number(r.changes)},null);}catch(e){cb&&cb(e);}}
  get(sql,p,cb){if(typeof p==='function'){cb=p;p=[];}try{cb&&cb(null,this.raw.prepare(sql).get(...(p||[])));}catch(e){cb&&cb(e);}}
  all(sql,p,cb){if(typeof p==='function'){cb=p;p=[];}try{cb&&cb(null,this.raw.prepare(sql).all(...(p||[])));}catch(e){cb&&cb(e);}}
}
const Module=require('module');const orig=Module._resolveFilename;
Module._resolveFilename=function(r,...a){return r==='sqlite3'?'shim':orig.call(this,r,...a);};
require.cache['shim']={id:'shim',filename:'shim',loaded:true,exports:ShimDb};
// node-pty cannot build in this sandbox; stub it (unrelated to the feature).
const ptyStub={spawn:()=>({onData(){},onExit(){},write(){},resize(){},kill(){},pause(){},resume(){},pid:1})};
const prev=Module._resolveFilename;
Module._resolveFilename=function(r,...a){return r==='node-pty'?'ptyshim':prev.call(this,r,...a);};
require.cache['ptyshim']={id:'ptyshim',filename:'ptyshim',loaded:true,exports:ptyStub};
process.env.TGVPANEL_DISABLE_RESELLER_POLLER='true';

const { UnifiedDatabase } = require(path.join(repo,'lib/db/database'));
const { runMigrations } = require(path.join(repo,'lib/db/migrations'));
const { ResellerService } = require(path.join(repo,'lib/services/reseller/ResellerService'));
const { NodeManager } = require(path.join(repo,'lib/services/nodes/NodeClient'));
const { LXCAdapter } = require(path.join(repo,'lib/services/virtualization/LXCAdapter'));
const { KVMAdapter } = require(path.join(repo,'lib/services/virtualization/KVMAdapter'));
const { VirtualizationManager } = require(path.join(repo,'lib/services/virtualization/VirtualizationManager'));

let pass=0, fail=0;
const check=(n,ok,d)=>{ok?(pass++,console.log('  PASS ',n,d||'')):(fail++,console.log('  FAIL ',n,d||''));};

(async()=>{
  const dbPath='/tmp/ownnode.db';
  if(fs.existsSync(dbPath))fs.unlinkSync(dbPath);
  const db=new UnifiedDatabase(new ShimDb(dbPath),dbPath);
  const mig=await runMigrations(db);
  console.log('schema:', mig.applied.slice(-2).join(', '), '\n');

  // --- a node we own
  await db.run(`INSERT INTO nodes (name,hostname,ip_address,url,is_local,status,health_status,cpu_model,cpu_cores,ram_total_mb,disk_total_gb,max_instances)
    VALUES ('node1','node1.local','10.0.0.5','http://127.0.0.1:5050',1,'online','online','AMD EPYC',16,65536,500,50)`);
  const nodeId=(await db.get(`SELECT id FROM nodes WHERE name='node1'`)).id;
  await db.run(`INSERT INTO lxc_templates (template_key,label,image_alias,slug,distro,release,arch,family,is_active) VALUES ('ubuntu-24-04','Ubuntu 24.04','ubuntu/24.04','ubuntu:24.04','ubuntu','24.04','amd64','debian',1)`);

  // --- wire the real virtualization stack
  const nodeManager=new NodeManager(db);
  // stub only the host call (no LXC in sandbox)
  nodeManager.localRuntime = { containerManager: {
    stopContainer: async () => ({ state: 'stopped' }),
    startContainer: async () => ({ state: 'running' }),
    restartContainer: async () => ({ state: 'running' }),
    destroyContainer: async () => true,
    inspectContainer: async () => ({ state: 'running', status: 'running', ips: ['10.0.0.77'] }),
    createContainer: async (spec) => ({
    state:'running', ips:['10.0.0.77'], configuredIpv4:'10.0.0.77', backingStore:'dir', configuredGateway:'10.0.0.1',
  }), }, };
  const kvm=new KVMAdapter(db,{});
  const lxc=new LXCAdapter(db,nodeManager);
  const virt=new VirtualizationManager(kvm,lxc);
  const svc=new ResellerService(db,virt);

  console.log('[1] capacity discovery from real node');
  const cap=await svc.getLocalCapacity();
  check('finds sellable shapes on our node', cap.length>0, `${cap.length} shapes`);
  if(cap.length) console.log(`        e.g. ${cap[0].upstreamPlanId} — ${cap[0].displayName} (x${cap[0].available})`);

  console.log('\n[2] create a LOCAL provider (no API key, no base URL)');
  const prov=await svc.createProvider({name:'My Own Nodes',baseUrl:'',provider:'local',enabled:true,storeEnabled:true,makeDefault:false});
  check('local provider created', !!prov.id, `id=${prov.id}`);
  check('no base URL required', !prov.base_url, JSON.stringify(prov.base_url));
  const ready=await svc.isProviderReady(prov.id);
  check('local provider is READY without an API key', ready.ready===true, ready.reason||'ok');

  console.log('\n[3] sync its catalogue from node capacity');
  const sync=await svc.syncCatalogue({providerId:prov.id});
  check('sync builds local plans', sync.plansUpserted>0, `${sync.plansUpserted} plans, ${sync.osUpserted} OS`);

  // Newly synced plans arrive disabled so an admin can set prices first,
  // exactly like upstream sync.
  const disabled=await svc.listPlans({providerId:prov.id, enabledOnly:false});
  check('plans start disabled (admin sets prices first)', disabled.length>0 && disabled.every(p=>!p.is_enabled), `${disabled.length} disabled`);

  // Admin enables one plan (the real workflow).
  const target=disabled.find(p=>p.engine==='lxc')||disabled[0];
  await db.run(`UPDATE reseller_plans SET is_enabled=1, retail_cents=500, retail_renew_cents=500, cost_cents=0 WHERE id=?`,[target.id]);
  const plans=await svc.listPlans({providerId:prov.id, enabledOnly:true});
  check('enabled plan is sellable', plans.length>0, `${plans.length} enabled`);
  const plan=plans.find(p=>p.id===target.id);
  check('plan knows its engine', !!plan.engine, String(plan.engine));
  check('plan knows its node', !!plan.node_id, String(plan.node_id));
  console.log(`        plan: ${plan.display_name} | ${plan.cores}c/${plan.memory_gb}GB/${plan.disk_gb}GB | engine=${plan.engine}`);

  console.log('\n[4] a customer buys it');
  await db.run(`INSERT INTO users (username,password,email,role,is_active) VALUES ('buyer','x','b@x.tld','user',1)`);
  const uid=(await db.get(`SELECT id FROM users WHERE username='buyer'`)).id;
  await svc.adjustWallet({userId:uid,amountCents:100000,kind:'credit',description:'seed'});

  const outcome=await svc.placeOrder({
    userId:uid, planId:plan.id, os:(plan.lxc_template||'ubuntu:24.04'), tos:true, cancellation:true,
  });
  check('order provisioned', outcome.status==='provisioned', outcome.status);
  check('server created for the customer', !!outcome.serverId, `serverId=${outcome.serverId}`);
  check('no upstream cost (own hardware)', outcome.costCents===0, `${outcome.costCents}`);

  console.log('\n[5] the server really exists as an LXC instance');
  const srv=await db.get(`SELECT * FROM cloud_servers WHERE id=?`,[outcome.serverId]);
  check('cloud_server linked to an instance', !!srv.instance_ref_id, `engine=${srv.engine} ref=${srv.instance_ref_id}`);
  // May land on any sellable node; it must be the node the plan was pinned to.
  check('cloud_server linked to the plan\'s node', Number(srv.node_id)===Number(plan.node_id), `planNode=${plan.node_id} serverNode=${srv.node_id}`);
  const inst=await db.get(`SELECT * FROM lxc_instances WHERE id=?`,[srv.instance_ref_id]);
  check('real lxc_instances row exists', !!inst, inst?`${inst.container_name} (${inst.status})`:'missing');
  check('IP assigned from the host', !!inst.ip_address, String(inst.ip_address));

  console.log('\n[6] customer can manage it (power actions)');
  const adapter=virt.getAdapter('lxc');
  const stopped=await adapter.performLifecycleAction(Number(srv.instance_ref_id),'stop');
  check('power action works on the sold server', !!stopped, stopped.status);

  console.log(`\n===== ${pass}/${pass+fail} checks passed =====`);
  process.exit(fail?1:0);
})().catch(e=>{console.error('CRASH:',e);process.exit(1);});
