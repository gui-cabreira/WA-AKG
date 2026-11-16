/** Local only. Requires a dedicated disposable PostgreSQL database. Never production. */
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { Server } from 'socket.io';
import { io as connectClient, Socket as ClientSocket } from 'socket.io-client';
import { encode } from 'next-auth/jwt';
import { prisma } from '../../src/lib/prisma';
import { setupSocket } from '../../src/server/socket';
const database = new URL(process.env.DATABASE_URL || '');
assert.equal(database.hostname,'127.0.0.1');assert.equal(database.pathname,'/wa_security_test');
const secret=process.env.AUTH_SECRET!;assert.ok(secret.startsWith('synthetic-test'));
const http=createServer();const io=new Server(http,{path:'/api/socket/io'});setupSocket(io);
await new Promise<void>(resolve=>http.listen(0,'127.0.0.1',resolve));
const address=http.address();assert.ok(address&&typeof address!=='string');const url=`http://127.0.0.1:${address.port}`;
const clients:ClientSocket[]=[];const fixtureIds:string[]=[];const suffix=Date.now().toString();const keyA=`synthetic-key-a-${suffix}`,keyB=`synthetic-key-b-${suffix}`;
const wait=async(fn:()=>boolean,ms=11000)=>{const end=Date.now()+ms;while(!fn()){if(Date.now()>end)throw Error('condition timeout');await new Promise(r=>setTimeout(r,30));}};
async function client(options:Parameters<typeof connectClient>[1],accepted=true){const c=connectClient(url,{path:'/api/socket/io',transports:['websocket'],reconnection:false,...options});clients.push(c);let connected=false,failed=false;c.once('connect',()=>connected=true);c.once('connect_error',()=>failed=true);await wait(()=>connected||failed,4000);assert.equal(connected,accepted);return c;}
async function denied(c:ClientSocket,event:string,value:string){let rejected=false;c.once('error',()=>rejected=true);c.emit(event,value);await wait(()=>rejected,3000);}
async function cookie(token:string,name='authjs.session-token',split=false){return client({extraHeaders:{Cookie:split?`${name}.1=${token.slice(100)}; ${name}.0=${token.slice(0,100)}`:`${name}=${token}`}});}
try {
 const a=await prisma.user.create({data:{email:`a-${suffix}@example.invalid`,password:'unused',role:'OWNER',apiKey:keyA}});
 const b=await prisma.user.create({data:{email:`b-${suffix}@example.invalid`,password:'unused',role:'OWNER',apiKey:keyB}});
 fixtureIds.push(a.id,b.id);
 const sa=await prisma.session.create({data:{name:'Synthetic A',sessionId:`synthetic-session-a-${suffix}`,userId:a.id}});
 const sb=await prisma.session.create({data:{name:'Synthetic B',sessionId:`synthetic-session-b-${suffix}`,userId:b.id}});
 await client({},false);await client({auth:{apiKey:'invalid'}},false);
 const ca=await client({auth:{apiKey:keyA}});const cb=await client({auth:{apiKey:keyB}});
 await denied(ca,'join-session',sb.sessionId);await denied(ca,'join-user-room',b.id);
 ca.emit('join-session',sa.sessionId);cb.emit('join-session',sb.sessionId);
 await wait(()=>io.sockets.sockets.get(ca.id!)?.rooms.has(sa.sessionId)===true&&io.sockets.sockets.get(cb.id!)?.rooms.has(sb.sessionId)===true);
 let aReceived=false,bReceived=false;ca.once('probe',()=>aReceived=true);cb.once('probe',()=>bReceived=true);io.to(sb.sessionId).emit('probe','synthetic');await wait(()=>bReceived,2000);assert.equal(aReceived,false);
 const token=await encode({token:{id:a.id,role:'SUPERADMIN'},secret,salt:'authjs.session-token',maxAge:60});
 const jwt=await cookie(token,'authjs.session-token',true);await denied(jwt,'join-session',sb.sessionId);
 const secure=await encode({token:{id:b.id,role:'OWNER'},secret,salt:'__Secure-authjs.session-token',maxAge:60});await cookie(secure,'__Secure-authjs.session-token');
 await prisma.sessionAccess.create({data:{userId:a.id,sessionId:sb.id}});ca.emit('join-session',sb.sessionId);await wait(()=>io.sockets.sockets.get(ca.id!)?.rooms.has(sb.sessionId)===true);
 await prisma.sessionAccess.deleteMany({where:{userId:a.id,sessionId:sb.id}});await wait(()=>io.sockets.sockets.get(ca.id!)?.rooms.has(sb.sessionId)===false);
 assert.equal(io.sockets.sockets.get(ca.id!)?.rooms.has(sa.sessionId),true);
 await prisma.user.update({where:{id:a.id},data:{apiKey:`${keyA}-rotated`}});await wait(()=>!ca.connected);
 const expiring=await encode({token:{id:b.id,role:'OWNER'},secret,salt:'authjs.session-token',maxAge:2});const ce=await cookie(expiring);await wait(()=>!ce.connected,5000);
 await prisma.user.delete({where:{id:a.id}});await wait(()=>!jwt.connected);
 console.log('PASS integrated PostgreSQL + actual Socket.IO + actual Auth.js tokens: 2 tenants, anonymous/wrong-key, cross-tenant joins/delivery, normal+secure chunked cookie, stale admin role, revoked sharing, own room retained, key rotation, JWT expiry, user deletion');
} finally {for(const c of clients)c.disconnect();await new Promise<void>(resolve=>io.close(()=>resolve()));await prisma.user.deleteMany({where:{id:{in:fixtureIds}}});await prisma.$disconnect();}
