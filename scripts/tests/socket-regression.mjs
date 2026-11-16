import fs from 'node:fs';import assert from 'node:assert/strict';import {stripTypeScriptTypes} from 'node:module';
let src=fs.readFileSync(new URL('../../src/server/socket.ts',import.meta.url),'utf8').replace(/^import .*;$/mg,'');
src=`const prisma=globalThis.__prisma; const canAccessSession=globalThis.__access; const logger={info(){},warn(){},error(){},debug(){}};\n`+src;
globalThis.__prisma={user:{findUnique:async({where})=>where.apiKey==='key-a'?{id:'a',role:'USER'}:null}};
globalThis.__access=async(user,role,session)=>user==='a'&&session==='session-a';
const {setupSocket}=await import('data:text/javascript;base64,'+Buffer.from(stripTypeScriptTypes(src)).toString('base64'));
let auth,connect;setupSocket({use(fn){auth=fn},on(event,fn){connect=fn}});
function socket(key){return {id:'test',data:{},handshake:{headers:{},auth:{apiKey:key}},handlers:{},joined:[],errors:[],on(e,fn){this.handlers[e]=fn},join(r){this.joined.push(r)},emit(e,v){this.errors.push(v)}};}
const anonymous=socket();await auth(anonymous,error=>assert.ok(error));
const valid=socket('key-a');await auth(valid,error=>assert.equal(error,undefined));connect(valid);
await valid.handlers['join-session']('session-b');assert.deepEqual(valid.joined,[]);
await valid.handlers['join-session']('session-a');assert.deepEqual(valid.joined,['session-a']);
valid.handlers['join-user-room']('b');assert.deepEqual(valid.joined,['session-a']);
valid.handlers['join-user-room']('a');assert.deepEqual(valid.joined,['session-a','user:a']);
console.log('PASS: anonymous rejected; authorized user accepted; other tenant session/user room blocked; own rooms allowed');
