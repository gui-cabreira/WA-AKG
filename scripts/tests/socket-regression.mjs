import fs from 'node:fs';import assert from 'node:assert/strict';import {stripTypeScriptTypes} from 'node:module';
let src=fs.readFileSync(new URL('../../src/server/socket.ts',import.meta.url),'utf8').replace(/^import .*;$/mg,'').replace('await import("next-auth/jwt")', '({decode: globalThis.__decode})');
src=`const prisma=globalThis.__prisma; const canAccessSession=globalThis.__access; const logger={info(){},warn(){},error(){},debug(){}};
const setInterval=globalThis.__setInterval,clearInterval=globalThis.__clearTimer,setTimeout=globalThis.__setTimeout,clearTimeout=globalThis.__clearTimer;\n`+src;
const timers=new Map();
function timer(fn,ms,kind){const id={unref(){}};timers.set(id,{fn,ms,kind});return id;}
globalThis.__setInterval=(fn,ms)=>timer(fn,ms,'interval');globalThis.__setTimeout=(fn,ms)=>timer(fn,ms,'timeout');globalThis.__clearTimer=id=>timers.delete(id);
process.env.AUTH_SECRET='synthetic-secret';let role='USER',exists=true,keyValid=true,share=true,dbFail=false,dbHang=false;
globalThis.__decode=async({token})=>token==='stale-admin'?{id:'a',role:'SUPERADMIN',exp:Date.now()/1000+60}:token==='deleted'?{id:'deleted',role:'SUPERADMIN',exp:Date.now()/1000+60}:null;
globalThis.__prisma={user:{findUnique:async({where})=>{if(dbFail)throw Error('DB unavailable');if(dbHang)return new Promise(()=>{});return exists&&((where.apiKey==='key-a'&&keyValid)||where.id==='a')?{id:'a',role,email:'test@example.invalid'}:null;}}};
globalThis.__access=async(user,userRole,session)=>userRole==='SUPERADMIN'||(user==='a'&&session==='session-a'&&share);
const {setupSocket}=await import('data:text/javascript;base64,'+Buffer.from(stripTypeScriptTypes(src)).toString('base64'));
let auth,connect;setupSocket({use(fn){auth=fn},on(event,fn){connect=fn}});
function socket(key){return {id:'test',connected:true,data:{},handshake:{headers:{},auth:{apiKey:key}},handlers:{},joined:[],errors:[],on(e,fn){this.handlers[e]=fn},join(r){if(!this.joined.includes(r))this.joined.push(r)},leave(r){this.joined=this.joined.filter(v=>v!==r)},disconnect(){this.connected=false;this.joined=[];this.handlers.disconnect?.()},emit(e,v){this.errors.push(v)}};}
async function tick(){for(const t of [...timers.values()])if(t.kind==='interval')t.fn();await new Promise(resolve=>setImmediate(resolve));}
async function connected(){const s=socket('key-a');await auth(s,e=>assert.equal(e,undefined));connect(s);return s;}
const jwt=socket();jwt.handshake.headers.cookie='authjs.session-token.1=admin; authjs.session-token.0=stale-';await auth(jwt,e=>assert.equal(e,undefined));assert.equal(jwt.data.user.role,'USER');
const deleted=socket();deleted.handshake.headers.cookie='authjs.session-token=deleted';await auth(deleted,e=>assert.ok(e));
await auth(socket(),e=>assert.ok(e));
const valid=await connected();await valid.handlers['join-session']('session-b');assert.deepEqual(valid.joined,[]);
await valid.handlers['join-session']('session-a');await valid.handlers['join-user-room']('a');await valid.handlers['join-user-room']('b');assert.deepEqual(valid.joined,['session-a','user:a']);
share=false;await tick();assert.deepEqual(valid.joined,['user:a']); // previously joined room removed
keyValid=false;await tick();assert.equal(valid.connected,false);assert.deepEqual(valid.joined,[]);assert.equal(timers.size,0);
keyValid=true;share=true;role='SUPERADMIN';const admin=await connected();await admin.handlers['join-session']('session-b');await admin.handlers['join-user-room']('b');role='USER';await tick();assert.deepEqual(admin.joined,[]);admin.disconnect();
const failure=await connected();dbFail=true;await tick();assert.equal(failure.connected,false);dbFail=false;
connect(jwt);jwt.data.expiresAt=Date.now()-1;await tick();assert.equal(jwt.connected,false);
const hung=await connected();dbHang=true;await tick();for(const t of [...timers.values()])if(t.kind==='timeout'&&t.ms===5000)t.fn();await new Promise(r=>setImmediate(r));assert.equal(hung.connected,false);dbHang=false;
const lease=await connected();for(const t of [...timers.values()])if(t.kind==='timeout'&&t.ms===15000)t.fn();assert.equal(lease.connected,false);assert.equal(timers.size,0);
console.log('PASS: authentication, chunked JWT, live role, cross-tenant rejection, revoked share eviction, key rotation, demotion, DB fail-closed, JWT expiry, lease expiry and timer cleanup');
