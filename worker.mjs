const encoder=new TextEncoder(),decoder=new TextDecoder(),SIDES=['ללא','כל הפיצה','חצי ימין','חצי שמאל'];
const noStore={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'same-origin'};
const json=(data,status=200)=>Response.json(data,{status,headers:noStore});
function cookie(request,name){return request.headers.get('Cookie')?.split(';').map(s=>s.trim()).find(s=>s.startsWith(name+'='))?.slice(name.length+1)}
const b64=bytes=>btoa(String.fromCharCode(...bytes)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const unb64=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
const sameOrigin=request=>request.headers.get('Origin')===new URL(request.url).origin;
async function readBody(request,max){const reader=request.body?.getReader();if(!reader)return '';let length=0;const chunks=[];while(true){const{done,value}=await reader.read();if(done)break;length+=value.byteLength;if(length>max){await reader.cancel();throw new Error('BODY_TOO_LARGE')}chunks.push(value)}const data=new Uint8Array(length);let offset=0;for(const chunk of chunks){data.set(chunk,offset);offset+=chunk.length}return decoder.decode(data)}
async function signingKey(env){if(!env.ADMIN_SESSION_SECRET)throw Error('SESSION_CONFIGURATION');return crypto.subtle.importKey('raw',encoder.encode(env.ADMIN_SESSION_SECRET),{name:'HMAC',hash:'SHA-256'},false,['sign','verify'])}
export async function makeSession(identity,env){const payload=b64(encoder.encode(JSON.stringify({identity,exp:Date.now()+28800000})));const sig=await crypto.subtle.sign('HMAC',await signingKey(env),encoder.encode(payload));return payload+'.'+b64(new Uint8Array(sig))}
export async function validSession(request,env,identity){try{if(!identity)return false;const token=cookie(request,'pizza_admin');if(!token)return false;const parts=token.split('.');if(parts.length!==2)return false;const data=JSON.parse(decoder.decode(unb64(parts[0])));if(data.identity!==identity||!Number.isFinite(data.exp)||data.exp<=Date.now()||data.exp>Date.now()+28800000)return false;return await crypto.subtle.verify('HMAC',await signingKey(env),unb64(parts[1]),encoder.encode(parts[0]))}catch{return false}}
export async function ownerIdentity(request,env){
 if(!env.ADMIN_EMAIL)return null;
 // Sites identity headers are trusted only when this code is deployed behind Sites dispatch.
 if(env.ADMIN_IDENTITY_MODE==='sites'){const email=request.headers.get('oai-authenticated-user-email'),uid=request.headers.get('oai-authenticated-user-id');return uid&&email?.toLowerCase()===env.ADMIN_EMAIL.toLowerCase()?uid:null}
 if(!env.ACCESS_TEAM_DOMAIN||!env.ACCESS_AUD)return null;
 const domain=env.ACCESS_TEAM_DOMAIN.replace(/^https:\/\//,'').replace(/\/$/,'');if(!/^[a-z0-9-]+\.cloudflareaccess\.com$/i.test(domain))return null;
 const token=request.headers.get('Cf-Access-Jwt-Assertion')||cookie(request,'CF_Authorization');if(!token)return null;
 try{const parts=token.split('.');if(parts.length!==3)return null;const header=JSON.parse(decoder.decode(unb64(parts[0]))),claims=JSON.parse(decoder.decode(unb64(parts[1])));if(header.alg!=='RS256'||claims.iss!=='https://'+domain||!Number.isFinite(claims.exp)||claims.exp<=Date.now()/1000||claims.nbf&&claims.nbf>Date.now()/1000+30||!(Array.isArray(claims.aud)?claims.aud:[claims.aud]).includes(env.ACCESS_AUD)||claims.email?.toLowerCase()!==env.ADMIN_EMAIL.toLowerCase())return null;
 const response=await fetch('https://'+domain+'/cdn-cgi/access/certs');if(!response.ok)return null;const{keys}=await response.json();const jwk=keys?.find(k=>k.kid===header.kid);if(!jwk)return null;const key=await crypto.subtle.importKey('jwk',jwk,{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['verify']);return await crypto.subtle.verify('RSASSA-PKCS1-v1_5',key,unb64(parts[2]),encoder.encode(parts[0]+'.'+parts[1]))?claims.sub:null;
 }catch{return null}
}
async function matchesPassword(value,expected){if(!expected)return false;const a=new Uint8Array(await crypto.subtle.digest('SHA-256',encoder.encode(value))),b=new Uint8Array(await crypto.subtle.digest('SHA-256',encoder.encode(expected)));let diff=0;for(let i=0;i<a.length;i++)diff|=a[i]^b[i];return diff===0}
async function api(request,env,path){
 if(path==='/api/admin/login'&&request.method==='POST'){
  if(!sameOrigin(request))return json({message:'בקשה לא מורשית'},403);
  if(!env.ADMIN_EMAIL||!env.ADMIN_PASSWORD||!env.ADMIN_SESSION_SECRET||(env.ADMIN_IDENTITY_MODE!=='sites'&&(!env.ACCESS_TEAM_DOMAIN||!env.ACCESS_AUD)))return json({message:'הגדרת חשבון הניהול בשרת טרם הושלמה. יש לפעול לפי הוראות ההתקנה.'},503);
  const identity=await ownerIdentity(request,env);if(!identity)return json({message:'נדרשת כניסה בחשבון הניהול המורשה דרך Cloudflare Access.'},403);
  const now=Date.now(),attempt=await env.DB.prepare('SELECT failures, window_start FROM admin_login_attempts WHERE identity=?').bind(identity).first();if(attempt&&now-attempt.window_start<900000&&attempt.failures>=10)return json({message:'בוצעו ניסיונות רבים. נסו שוב בעוד מספר דקות.'},429);
  const form=new URLSearchParams(await readBody(request,2048)),password=form.get('password')||'';
  if(password.length>200||!await matchesPassword(password,env.ADMIN_PASSWORD)){const active=attempt&&now-attempt.window_start<900000;await env.DB.prepare('INSERT INTO admin_login_attempts (identity,failures,window_start) VALUES (?,?,?) ON CONFLICT(identity) DO UPDATE SET failures=excluded.failures,window_start=excluded.window_start').bind(identity,active?attempt.failures+1:1,active?attempt.window_start:now).run();return json({message:'הסיסמה שגויה. נסו שוב.'},401)}
  await env.DB.prepare('DELETE FROM admin_login_attempts WHERE identity=?').bind(identity).run();const token=await makeSession(identity,env);return Response.json({ok:true},{headers:{...noStore,'Set-Cookie':'pizza_admin='+token+'; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=28800'}})
 }
 if(path==='/api/admin/logout'&&request.method==='POST'){if(!sameOrigin(request))return json({error:'Forbidden'},403);return Response.json({ok:true},{headers:{...noStore,'Set-Cookie':'pizza_admin=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0'}})}
 if(path==='/api/orders'&&request.method==='POST'){
  if(!sameOrigin(request))return json({error:'Forbidden'},403);if(!request.headers.get('Content-Type')?.includes('application/json'))return json({error:'JSON required'},415);
  let body;try{body=JSON.parse(await readBody(request,100000))}catch(error){if(error.message==='BODY_TOO_LARGE')throw error;return json({error:'Invalid JSON'},400)}
  if(!body||typeof body!=='object')return json({error:'Invalid body'},400);const{requestId,orders}=body;const quantity=x=>Number.isInteger(x)&&x>=0&&x<=100;
  if(typeof requestId!=='string'||!/^[a-zA-Z0-9-]{8,80}$/.test(requestId)||!Array.isArray(orders)||!orders.length||orders.length>100)return json({error:'Invalid order'},400);
  for(const o of orders)if(!o||typeof o.name!=='string'||!o.name.trim()||o.name.length>80||!quantity(o.pizzas)||!quantity(o.potato)||!Array.isArray(o.tops)||o.tops.length!==6||!o.tops.every(s=>SIDES.includes(s))||!Array.isArray(o.drinks)||o.drinks.length!==9||!o.drinks.every(quantity)||o.pizzas+o.potato+o.drinks.reduce((a,b)=>a+b,0)===0)return json({error:'Invalid fields'},400);
  const now=new Date().toISOString();await env.DB.batch(orders.map((o,i)=>env.DB.prepare('INSERT INTO pizza_orders (id,batch_id,payload,created_at) VALUES (?,?,?,?) ON CONFLICT(id) DO NOTHING').bind(requestId+'-'+i,requestId,JSON.stringify({name:o.name.trim(),pizzas:o.pizzas,tops:o.tops,drinks:o.drinks,potato:o.potato}),now)));return json({ok:true,number:requestId.slice(0,8).toUpperCase()})
 }
 if(path==='/api/orders'&&request.method==='GET'||path.startsWith('/api/orders/')&&request.method==='DELETE'){
  const identity=await ownerIdentity(request,env);if(!await validSession(request,env,identity))return json({error:'Unauthorized'},401);
  if(request.method==='GET'){const result=await env.DB.prepare('SELECT id,payload,created_at FROM pizza_orders ORDER BY created_at DESC,id').all();return json({orders:result.results.map(row=>({...JSON.parse(row.payload),id:row.id,createdAt:row.created_at}))})}
  if(!sameOrigin(request))return json({error:'Forbidden'},403);const id=decodeURIComponent(path.slice('/api/orders/'.length));if(!/^[a-zA-Z0-9-]{1,100}$/.test(id))return json({error:'Invalid ID'},400);await env.DB.prepare('DELETE FROM pizza_orders WHERE id=?').bind(id).run();return json({ok:true})
 }
 return json({error:'Not found'},404)
}
export default {async fetch(request,env){try{const url=new URL(request.url);if(url.pathname.startsWith('/api/'))return await api(request,env,url.pathname);if(!['GET','HEAD'].includes(request.method))return new Response('Method not allowed',{status:405});if(url.pathname==='/')url.pathname='/index.html';if(['/admin','/manage'].includes(url.pathname))url.pathname='/admin.html';if(!['/index.html','/admin.html'].includes(url.pathname))return new Response('Not found',{status:404});const response=await env.ASSETS.fetch(new Request(url,request));const headers=new Headers(response.headers);headers.set('X-Content-Type-Options','nosniff');headers.set('Referrer-Policy','same-origin');if(url.pathname==='/admin.html')headers.set('Cache-Control','no-store');return new Response(response.body,{status:response.status,headers})}catch(error){return json({error:error.message==='BODY_TOO_LARGE'?'Request too large':'Server error'},error.message==='BODY_TOO_LARGE'?413:500)}}};
