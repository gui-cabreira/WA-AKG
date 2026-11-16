import fs from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import dns from 'node:dns';
import https from 'node:https';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import assert from 'node:assert/strict';
const source = fs.readFileSync(new URL('../../src/lib/security.ts', import.meta.url), 'utf8');
const mod = await import('data:text/javascript;base64,'+Buffer.from(stripTypeScriptTypes(source)).toString('base64'));
const {isPrivateOrReservedIp, validateSafeUrl,safeFetchBuffer,materializeSafeMediaPayload}=mod;
for(const ip of ['127.0.0.1','10.0.0.2','::1','::ffff:127.0.0.1','0:0:0:0:0:ffff:7f00:1','fd00::1','fe80::1']) assert.equal(isPrivateOrReservedIp(ip),true,ip);
assert.equal(isPrivateOrReservedIp('93.184.216.34'),false);
const lookup=dns.promises.lookup, request=https.request;
let calls=0; dns.promises.lookup=async()=>[{address:'93.184.216.34',family:4}];
function mockRequest(delay=0,bytes=1,status=200) {
 https.request=(url, options, cb)=>{
   calls++;
   options.lookup(url.hostname,{},(err,ip)=>assert.equal(ip,'93.184.216.34'));
   const req=new EventEmitter(); let timer;req.destroy=()=>clearTimeout(timer);
   req.end=()=>{const response=new PassThrough();response.statusCode=status;response.headers={};cb(response);timer=setTimeout(()=>response.end(Buffer.alloc(bytes)),delay);};return req;
 };
}
try {
 mockRequest(); assert.equal((await safeFetchBuffer('https://example.com')).buffer.length,1);
 mockRequest(100); await assert.rejects(safeFetchBuffer('https://example.com',{timeoutMs:10}),/deadline/);
 mockRequest(0,10); await assert.rejects(safeFetchBuffer('https://example.com',{maxBytes:2}),/size/);
 mockRequest(0,1,600); await assert.rejects(safeFetchBuffer('https://example.com'),/Unsupported remote/);
 const before=calls; dns.promises.lookup=async()=>[{address:'0:0:0:0:0:ffff:7f00:1',family:6}];
 await assert.rejects(safeFetchBuffer('https://example.com'),/SSRF/);assert.equal(calls,before);
 for(const media of ['image','video','document','audio','sticker']) await assert.rejects(materializeSafeMediaPayload({[media]:{url:'/etc/passwd'}}));
 assert.equal((await validateSafeUrl('https://user:pass@example.com')).valid,false);
 console.log('PASS: IP ranges, DNS pinning, body deadline, size, private DNS, local paths, URL credentials');
} finally {dns.promises.lookup=lookup;https.request=request;}
// Wiring regression: all background media entrypoints must go through the shared guard.
const root = new URL('../../', import.meta.url);
for (const path of ['src/lib/cron.ts','src/modules/whatsapp/store/autoreply.ts']) {
 const code=fs.readFileSync(new URL(path,root),'utf8');
 assert.match(code,/sendMessage\([^\n]*await materializeSafeMediaPayload\(payload\)/);
}
const scheduler=fs.readFileSync(new URL('src/modules/whatsapp/scheduler.ts',root),'utf8');
assert.match(scheduler,/await safeFetchBuffer\(url/);assert.doesNotMatch(scheduler,/await fetch\(url/);
console.log('PASS: background media guard wiring');
