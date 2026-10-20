import test from 'node:test';import assert from 'node:assert/strict';import{readFileSync}from'node:fs';import{Script}from'node:vm';import worker,{makeSession,validSession,ownerIdentity}from'./worker.mjs';
function setup(){
 const data=new Map(),attempts=new Map();
 const DB={
  prepare(sql){return {
   bind(...args){return {sql,args,
    async first(){return attempts.get(args[0])||null},
    async run(){
     if(sql.startsWith('DELETE FROM pizza_orders'))data.delete(args[0]);
     if(sql.startsWith('DELETE FROM admin_login_attempts'))attempts.delete(args[0]);
     if(sql.startsWith('INSERT INTO admin_login_attempts'))attempts.set(args[0],{failures:args[1],window_start:args[2]});
     return {success:true};
    }
   }},
   async all(){return {results:[...data.values()]}}
  }},
  async batch(rows){for(const {args:a} of rows)if(!data.has(a[0]))data.set(a[0],{id:a[0],payload:a[2],created_at:a[3]});return []}
 };
 const env={ADMIN_IDENTITY_MODE:'sites',ADMIN_EMAIL:'owner@example.test',ADMIN_PASSWORD:'test-only-password',ADMIN_SESSION_SECRET:'test-only-session-signing-key',DB,
 ASSETS:{async fetch(request){return new Response(new URL(request.url).pathname,{headers:{'Content-Type':'text/html'}})}}};
 return {env,data};
}
const origin='https://pizza.test',owner={'oai-authenticated-user-id':'owner-id','oai-authenticated-user-email':'owner@example.test'},send=(path,method='GET',body,headers={})=>new Request(origin+path,{method,headers:{Origin:origin,...headers},body});
const order={name:'לקוחה',pizzas:2,tops:['כל הפיצה','חצי שמאל','חצי ימין','ללא','ללא','ללא'],drinks:[1,0,0,0,0,0,2,3,1],potato:1};
test('HTML embeds images and executable scripts, with every product retained',()=>{const html=readFileSync(new URL('./index.html',import.meta.url),'utf8');assert(html.includes('data:image/png;base64,'));assert(!html.includes('src="/app.js"'));assert(!html.includes('href="/style.css"'));for(const match of html.matchAll(/<script>([\s\S]*?)<\/script>/g))new Script(match[1]);for(const name of ['גמבה אדומה','תפוח אדמה מוקרם','ZERO','תפוזים','בירה','הזמן פיצה נוספת','סיום הזמנה'])assert(html.includes(name));assert(html.includes('position:sticky'));const admin=readFileSync(new URL('./admin.html',import.meta.url),'utf8');for(const match of admin.matchAll(/<script>([\s\S]*?)<\/script>/g))new Script(match[1]);assert(admin.includes('workbook('));assert(admin.includes('חיפוש לפי שם לקוח'))});
test('order persistence, retry deduplication, validation and private reads',async()=>{const{env,data}=setup();const body=JSON.stringify({requestId:'request-000001',orders:[order]}),headers={'Content-Type':'application/json'};let r=await worker.fetch(send('/api/orders','POST',body,headers),env);assert.equal(r.status,200);r=await worker.fetch(send('/api/orders','POST',body,headers),env);assert.equal(data.size,1);r=await worker.fetch(send('/api/orders'),env);assert.equal(r.status,401);r=await worker.fetch(send('/api/orders','POST',body,{...headers,Origin:'https://wrong.test'}),env);assert.equal(r.status,403);r=await worker.fetch(send('/api/orders','POST',JSON.stringify({requestId:'request-000002',orders:[{...order,drinks:[]}]}),headers),env);assert.equal(r.status,400)});
test('password and owner identity are both required; signed session and delete',async()=>{const{env}=setup();assert.equal(await ownerIdentity(send('/admin'),env),null);let r=await worker.fetch(send('/api/admin/login','POST',new URLSearchParams({password:'wrong'}),owner),env);assert.equal(r.status,401);r=await worker.fetch(send('/api/admin/login','POST',new URLSearchParams({password:env.ADMIN_PASSWORD}),owner),env);assert.equal(r.status,200);const cookie=r.headers.get('Set-Cookie');assert(cookie.includes('HttpOnly'));assert(cookie.includes('SameSite=Strict'));const auth={...owner,Cookie:cookie.split(';')[0]};assert(await validSession(send('/admin','GET',undefined,auth),env,'owner-id'));assert(!await validSession(send('/admin','GET',undefined,{...auth,Cookie:auth.Cookie+'broken'}),env,'owner-id'));r=await worker.fetch(send('/api/orders','GET',undefined,auth),env);assert.equal(r.status,200);r=await worker.fetch(send('/api/orders/request-000001-0','DELETE',undefined,auth),env);assert.equal(r.status,200);r=await worker.fetch(send('/api/admin/logout','POST'),env);assert(r.headers.get('Set-Cookie').includes('Max-Age=0'))});
test('missing Access settings fail closed and do not trust client email headers',async()=>{const{env}=setup();env.ADMIN_IDENTITY_MODE='access';assert.equal(await ownerIdentity(send('/admin','GET',undefined,owner),env),null);const r=await worker.fetch(send('/api/admin/login','POST',new URLSearchParams({password:env.ADMIN_PASSWORD}),owner),env);assert.equal(r.status,503)});
test('static routes resolve and server source is never served',async()=>{const{env}=setup();let r=await worker.fetch(send('/'),env);assert.equal(await r.text(),'/index.html');r=await worker.fetch(send('/admin'),env);assert.equal(await r.text(),'/admin.html');r=await worker.fetch(send('/worker.mjs'),env);assert.equal(r.status,404)});
