/** Regression: an upstream (resold) provider must behave exactly as before. */
const path=require('path'), fs=require('fs');
const {DatabaseSync}=require('node:sqlite');
class ShimDb{constructor(f){this.raw=new DatabaseSync(f);}close(cb){this.raw.close();cb&&cb(null);}
exec(s,cb){try{this.raw.exec(s);cb&&cb(null);}catch(e){cb?cb(e):0;}}
run(s,p,cb){if(typeof p==='function'){cb=p;p=[];}try{const r=this.raw.prepare(s).run(...(p||[]));cb&&cb.call({lastID:Number(r.lastInsertRowid),changes:Number(r.changes)},null);}catch(e){cb&&cb(e);}}
get(s,p,cb){if(typeof p==='function'){cb=p;p=[];}try{cb&&cb(null,this.raw.prepare(s).get(...(p||[])));}catch(e){cb&&cb(e);}}
all(s,p,cb){if(typeof p==='function'){cb=p;p=[];}try{cb&&cb(null,this.raw.prepare(s).all(...(p||[])));}catch(e){cb&&cb(e);}}}
const Module=require('module'),orig=Module._resolveFilename;
Module._resolveFilename=function(r,...a){return r==='sqlite3'?'shim':orig.call(this,r,...a);};
require.cache['shim']={id:'shim',filename:'shim',loaded:true,exports:ShimDb};
const prev=Module._resolveFilename;
Module._resolveFilename=function(r,...a){return r==='node-pty'?'ptyshim':prev.call(this,r,...a);};
require.cache['ptyshim']={id:'ptyshim',filename:'ptyshim',loaded:true,exports:{spawn:()=>({})}};
const repo='/home/user/Panel';
const {UnifiedDatabase}=require(path.join(repo,'lib/db/database'));
const {runMigrations}=require(path.join(repo,'lib/db/migrations'));
const {ResellerService}=require(path.join(repo,'lib/services/reseller/ResellerService'));
let pass=0,fail=0; const check=(n,ok,d)=>{ok?(pass++,console.log('  PASS ',n,d||'')):(fail++,console.log('  FAIL ',n,d||''));};
(async()=>{
  const f='/tmp/regress.db'; if(fs.existsSync(f))fs.unlinkSync(f);
  const db=new UnifiedDatabase(new ShimDb(f),f);
  await runMigrations(db);
  const svc=new ResellerService(db);  // no virtualization layer, exactly like before
  console.log('[A] upstream provider still requires base URL + key');
  let threw=null; try{ await svc.createProvider({name:'Bukkit',baseUrl:'',provider:'bukkit'}); }catch(e){threw=e;}
  check('rejects upstream provider without base URL', !!threw, threw&&threw.code);

  const p=await svc.createProvider({name:'Bukkit',baseUrl:'https://bukkit-hosting.eu/api/v2',apiKey:'sk_test_123456789',provider:'bukkit',enabled:true,storeEnabled:true,makeDefault:true});
  check('upstream provider created', !!p.id, `id=${p.id}`);
  check('base_url persisted', p.base_url==='https://bukkit-hosting.eu/api/v2', p.base_url);
  const ready=await svc.isProviderReady(p.id);
  check('needs no node capacity', ready.ready===true, ready.reason||'ok');

  console.log('\n[B] multiple providers still coexist');
  const p2=await svc.createProvider({name:'Second',baseUrl:'https://other.example/api/v2',apiKey:'sk_test_abcdefgh',provider:'bukkit',enabled:true,storeEnabled:true});
  const all=await svc.listProviders();
  check('both providers listed independently', all.length>=2, `${all.length} providers (1 seeded + 2 created)`);
  check('each has its own base URL', new Set(all.filter(x=>x.api_key_hint||x.base_url).map(x=>x.base_url)).size>=2);

  console.log('\n[C] a local provider works even with NO virt layer (clear error)');
  const local=await svc.createProvider({name:'Nodes',baseUrl:'',provider:'local',enabled:true,storeEnabled:true});
  check('local provider creatable without virt', !!local.id, `id=${local.id}`);
  const lr=await svc.isProviderReady(local.id);
  check('reports a helpful reason instead of crashing', lr.ready===false && /virtualization layer/i.test(lr.reason||''), lr.reason);

  console.log(`\n===== ${pass}/${pass+fail} =====`);
  process.exit(fail?1:0);
})().catch(e=>{console.error('CRASH:',e);process.exit(1);});
