import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';
const ROOT=path.dirname(fileURLToPath(import.meta.url));
const DATA=path.join(ROOT,'data.json');
const PORT=Number(process.env.PORT||3000);
const OWNER_KEY=process.env.OWNER_ADMIN_KEY;
if(!OWNER_KEY || OWNER_KEY.length<12){console.error('Defina OWNER_ADMIN_KEY com uma chave forte de pelo menos 12 caracteres.');process.exit(1)}
let db=fs.existsSync(DATA)?JSON.parse(fs.readFileSync(DATA,'utf8')):{players:[],codes:[],logs:[],admins:[]};
for (const pl of db.players) { pl.bestDistance=Number(pl.bestDistance)||0; pl.bestTime=Number(pl.bestTime)||0; pl.matches=Number(pl.matches)||0; pl.skins=Array.isArray(pl.skins)?pl.skins:[]; pl.coinSkins=Array.isArray(pl.coinSkins)?pl.coinSkins:[]; }
for (const c of db.codes) c.redeemedBy=Array.isArray(c.redeemedBy)?c.redeemedBy:[];
const sessions=new Map(), runs=new Map(), rate=new Map();
const save=()=>{const tmp=DATA+'.tmp';fs.writeFileSync(tmp,JSON.stringify(db,null,2));fs.renameSync(tmp,DATA)};
const id=()=>crypto.randomUUID(); const hash=s=>crypto.createHash('sha256').update(String(s)).digest('hex');
const safe=(s,n=80)=>String(s??'').trim().slice(0,n);
const parseCookies=req=>Object.fromEntries((req.headers.cookie||'').split(';').map(x=>x.trim().split('=').map(decodeURIComponent)).filter(x=>x.length===2));
function send(res,status,obj,headers={}){res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',...headers});res.end(JSON.stringify(obj))}
async function body(req){let s='';for await(const c of req){s+=c;if(s.length>1e6)throw Error('Corpo muito grande')}return s?JSON.parse(s):{}}
function session(req){const c=parseCookies(req);return sessions.get(c.vitin_session)||null}
function auth(req,res,role='admin'){const s=session(req);if(!s||!s.admin||s.expires<Date.now()){send(res,401,{error:'Sessão expirada. Entre novamente.'});return null}if(role==='owner'&&s.role!=='owner'){send(res,403,{error:'Somente o proprietário principal pode fazer isso.'});return null}return s}
function playerAuth(req,res){const token=req.headers['x-player-token'];const p=db.players.find(x=>x.tokenHash===hash(token||''));if(!p){send(res,401,{error:'Jogador não autenticado.'});return null}return p}
function log(admin,action,player,details={}){db.logs.unshift({id:id(),date:new Date().toISOString(),admin,action,player:player||'',details});db.logs=db.logs.slice(0,1000)}
function publicPlayer(p){return {id:p.id,nickname:p.nickname,coins:p.coins,skins:p.skins,coinSkins:p.coinSkins,bestDistance:p.bestDistance||0,bestTime:p.bestTime||0,matches:p.matches||0}}
const skins=['skater','girlgamer','panda','fox','alien','skeleton','shark'];
const server=http.createServer(async(req,res)=>{
 try{
  const url=new URL(req.url,`http://${req.headers.host||'localhost'}`);const p=url.pathname;const method=req.method;
  if(method==='GET'&&p==='/health'){return send(res,200,{ok:true})}
  if(method==='GET'&&p==='/api/leaderboard'){
   const players=[...db.players].filter(x=>(Number(x.bestDistance)||0)>0).sort((a,b)=>(b.bestDistance||0)-(a.bestDistance||0)||(a.bestTime||0)-(b.bestTime||0)).slice(0,20).map(x=>({nickname:x.nickname,bestDistance:x.bestDistance||0,bestTime:x.bestTime||0,matches:x.matches||0}));
   return send(res,200,{players});
  }
  if(method==='POST'&&p==='/api/admin/login'){
   const ip=req.socket.remoteAddress||'unknown';const now=Date.now();const r=rate.get(ip)||{n:0,t:now};if(now-r.t>60000){r.n=0;r.t=now}if(r.n>=10)return send(res,429,{error:'Muitas tentativas. Aguarde um minuto.'});r.n++;rate.set(ip,r);
   const b=await body(req);let role=null,adminName='';if(crypto.timingSafeEqual(Buffer.from(hash(b.key||'')),Buffer.from(hash(OWNER_KEY)))){role='owner';adminName='Proprietário'}else{const a=db.admins.find(x=>x.active&&x.keyHash===hash(b.key||''));if(a){role='admin';adminName=a.name}}
   if(!role)return send(res,401,{error:'Chave incorreta.'});const sid=crypto.randomBytes(32).toString('hex');sessions.set(sid,{admin:adminName,role,expires:Date.now()+7200000});return send(res,200,{ok:true,role,admin:adminName},{'Set-Cookie':`vitin_session=${sid}; HttpOnly; SameSite=Lax; Path=/; Max-Age=7200`});
  }
  if(method==='POST'&&p==='/api/admin/logout'){const sid=parseCookies(req).vitin_session;sessions.delete(sid);return send(res,200,{ok:true},{'Set-Cookie':'vitin_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0'})}
  if(p.startsWith('/api/admin/')){
   const s=auth(req,res);if(!s)return;const who=s.admin;
   if(method==='GET'&&p==='/api/admin/summary')return send(res,200,{players:db.players.length,codes:db.codes.length,redemptions:db.codes.reduce((n,c)=>n+c.uses,0),actions:db.logs.length});
   if(method==='GET'&&p==='/api/admin/codes')return send(res,200,{codes:db.codes.map(c=>({...c,skinName:c.skinKey||'Moedas'}))});
   if(method==='POST'&&p==='/api/admin/codes'){const b=await body(req);let code=safe(b.code,40).toUpperCase().replace(/[^A-Z0-9-]/g,'')||crypto.randomBytes(5).toString('hex').toUpperCase();if(db.codes.some(c=>c.code===code))return send(res,409,{error:'Esse código já existe.'});const c={id:id(),code,skinKey:skins.includes(b.skinKey)?b.skinKey:'skater',maxUses:b.unlimited?null:Math.max(1,Math.min(1000000,Number(b.maxUses)||1)),uses:0,redeemedBy:[],active:true,createdAt:new Date().toISOString(),expiresAt:b.expiresAt||null};db.codes.push(c);log(who,'CRIAR_CODIGO','',{code,skinKey:c.skinKey});save();return send(res,201,{code:c})}
   const cm=p.match(/^\/api\/admin\/codes\/([^/]+)$/);if(cm){const c=db.codes.find(x=>x.id===cm[1]);if(!c)return send(res,404,{error:'Código não encontrado.'});if(method==='PATCH'){const b=await body(req);c.active=!!b.active;save();log(who,'ALTERAR_CODIGO','',{code:c.code,active:c.active});save();return send(res,200,{code:c})}if(method==='DELETE'){db.codes=db.codes.filter(x=>x.id!==c.id);log(who,'EXCLUIR_CODIGO','',{code:c.code});save();return send(res,200,{ok:true})}}
   if(method==='GET'&&p==='/api/admin/players'){const q=safe(url.searchParams.get('q'),100).toLowerCase();const players=db.players.filter(x=>x.nickname.toLowerCase().includes(q)||x.id.toLowerCase()===q).slice(0,50);return send(res,200,{players:players.map(x=>({...publicPlayer(x)}))})}
   const pm=p.match(/^\/api\/admin\/players\/([^/]+)\/coins$/);if(pm&&method==='POST'){const b=await body(req);const pl=db.players.find(x=>x.id===pm[1]);if(!pl)return send(res,404,{error:'Jogador não encontrado.'});const amount=Number(b.amount);if(!Number.isSafeInteger(amount)||amount<1||amount>1e9||!['add','remove'].includes(b.action))return send(res,400,{error:'Quantidade ou operação inválida.'});const old=pl.coins;if(b.action==='remove'&&amount>old)return send(res,400,{error:'Saldo insuficiente para remover.'});pl.coins=b.action==='add'?old+amount:old-amount;if(!Number.isSafeInteger(pl.coins))return send(res,400,{error:'Saldo excede o limite.'});log(who,b.action==='add'?'ADICIONAR_MOEDAS':'REMOVER_MOEDAS',pl.nickname,{amount,oldCoins:old,newCoins:pl.coins,playerId:pl.id});save();return send(res,200,{newCoins:pl.coins})}
   if(method==='GET'&&p==='/api/admin/logs')return send(res,200,{logs:db.logs.slice(0,200)});
   if(method==='GET'&&p==='/api/admin/admins'){if(s.role!=='owner')return send(res,403,{error:'Somente o proprietário pode gerenciar administradores.'});return send(res,200,{admins:db.admins.map(({id,name,active,createdAt})=>({id,name,active,createdAt}))})}
   if(method==='POST'&&p==='/api/admin/admins'){if(s.role!=='owner')return send(res,403,{error:'Somente o proprietário pode adicionar administradores.'});const b=await body(req),name=safe(b.name,40),key=safe(b.key,128);if(name.length<2||key.length<12)return send(res,400,{error:'Informe nome e chave com pelo menos 12 caracteres.'});if(hash(key)===hash(OWNER_KEY)||db.admins.some(a=>a.keyHash===hash(key)))return send(res,409,{error:'Essa chave já está em uso.'});const a={id:id(),name,keyHash:hash(key),active:true,createdAt:new Date().toISOString()};db.admins.push(a);log(who,'CRIAR_ADMIN','',{admin:name});save();return send(res,201,{admin:{id:a.id,name:a.name,active:a.active,createdAt:a.createdAt}})}
   const am=p.match(/^\/api\/admin\/admins\/([^/]+)$/);if(am&&method==='DELETE'){if(s.role!=='owner')return send(res,403,{error:'Somente o proprietário pode remover administradores.'});const a=db.admins.find(x=>x.id===am[1]);if(!a)return send(res,404,{error:'Administrador não encontrado.'});db.admins=db.admins.filter(x=>x.id!==a.id);log(who,'REMOVER_ADMIN','',{admin:a.name});save();return send(res,200,{ok:true})}
   return send(res,404,{error:'Rota administrativa não encontrada.'});
  }
  if(p.startsWith('/api/player/')){
   if(p==='/api/player/bootstrap'&&method==='POST'){const b=await body(req);let token=req.headers['x-player-token'];if(!/^[a-f0-9]{64}$/i.test(token||''))return send(res,400,{error:'Token de jogador inválido.'});let pl=db.players.find(x=>x.tokenHash===hash(token));if(!pl){pl={id:id(),tokenHash:hash(token),nickname:safe(b.nickname,30)||'Jogador',coins:Math.max(0,Math.min(10000000,Math.floor(Number(b.initialCoins)||0))),skins:skins.filter(k=>(Array.isArray(b.initialSkins)?b.initialSkins:[]).includes(k)),coinSkins:[],bestDistance:0,bestTime:0,matches:0,createdAt:new Date().toISOString()};db.players.push(pl);log('Sistema','NOVO_JOGADOR',pl.nickname,{playerId:pl.id});save()}else{pl.nickname=safe(b.nickname,30)||pl.nickname}return send(res,200,{player:publicPlayer(pl),skins:pl.skins,coinSkins:pl.coinSkins})}
   const pl=playerAuth(req,res);if(!pl)return;
   if(p==='/api/player/transfer'&&method==='POST'){
    const b=await body(req),targetId=safe(b.targetId,64),amount=Number(b.amount);
    if(!targetId||targetId===pl.id)return send(res,400,{error:'Informe o ID de outro jogador.'});
    if(!Number.isSafeInteger(amount)||amount<1||amount>1000000)return send(res,400,{error:'A quantidade deve ser de 1 a 1.000.000 moedas.'});
    const target=db.players.find(x=>x.id===targetId);if(!target)return send(res,404,{error:'Jogador não encontrado. Confira o ID.'});
    if(pl.coins<amount)return send(res,400,{error:'Você não tem moedas suficientes.'});
    pl.coins-=amount;target.coins+=amount;
    log('Sistema','DOACAO_MOEDAS',pl.nickname,{to:target.nickname,toId:target.id,amount,fromId:pl.id});save();
    return send(res,200,{player:publicPlayer(pl),recipient:{id:target.id,nickname:target.nickname,coins:target.coins}});
   }
   if(p==='/api/player/redeem'&&method==='POST'){const b=await body(req),code=safe(b.code,40).toUpperCase(),c=db.codes.find(x=>x.code===code&&x.active);if(!c)return send(res,400,{error:'Código inválido ou desativado.'});if(c.expiresAt&&Date.now()>Date.parse(c.expiresAt))return send(res,400,{error:'Esse código expirou.'});if(c.redeemedBy.includes(pl.id))return send(res,400,{error:'Você já resgatou este código.'});if(c.maxUses!==null&&c.uses>=c.maxUses)return send(res,400,{error:'Limite de resgates atingido.'});if(!pl.skins.includes(c.skinKey))pl.skins.push(c.skinKey);c.uses++;c.redeemedBy.push(pl.id);log('Sistema','RESGATAR_CODIGO',pl.nickname,{code,skinKey:c.skinKey});save();return send(res,200,{player:publicPlayer(pl),skins:pl.skins,coinSkins:pl.coinSkins,skinName:c.skinKey})}
   if(p==='/api/player/start-run'&&method==='POST'){const runId=id();runs.set(runId,{playerId:pl.id,at:Date.now()});return send(res,200,{runId})}
   if(p==='/api/player/run-reward'&&method==='POST'){const b=await body(req),r=runs.get(b.runId);if(!r||r.playerId!==pl.id||Date.now()-r.at>3600000)return send(res,400,{error:'Partida inválida ou expirada.'});runs.delete(b.runId);const dist=Math.max(0,Math.min(100000,Math.floor(Number(b.distance)||0)));const seconds=Math.max(0,Math.min(3600,Math.floor(Number(b.seconds)||0)));const collected=Math.max(0,Math.min(5000,Math.floor(Number(b.collectedCoins)||0)));const earned=Math.max(10,Math.floor(seconds*2+dist*.08))+collected;pl.coins+=earned;pl.matches=(pl.matches||0)+1;if(dist>(pl.bestDistance||0)){pl.bestDistance=dist;pl.bestTime=seconds}else if(!pl.bestTime||seconds<pl.bestTime){pl.bestTime=seconds}log('Sistema','RECOMPENSA_PARTIDA',pl.nickname,{amount:earned,distance:dist,seconds,collectedCoins:collected});save();return send(res,200,{player:publicPlayer(pl),reward:earned,skins:pl.skins,coinSkins:pl.coinSkins})}
   if(p==='/api/player/buy-skin'&&method==='POST'){const b=await body(req);if(!skins.includes(b.skinKey))return send(res,400,{error:'Skin inválida.'});if(pl.skins.includes(b.skinKey))return send(res,400,{error:'Skin já desbloqueada.'});const cost=500;if(pl.coins<cost)return send(res,400,{error:'Moedas insuficientes.'});pl.coins-=cost;pl.skins.push(b.skinKey);save();return send(res,200,{player:publicPlayer(pl),skins:pl.skins,coinSkins:pl.coinSkins})}
   if(p==='/api/player/buy-coin-look'&&method==='POST'){const b=await body(req);const costs={gold:1000,diamond:2500};if(!costs[b.key])return send(res,400,{error:'Visual inválido.'});if(pl.coins<costs[b.key])return send(res,400,{error:'Moedas insuficientes.'});pl.coins-=costs[b.key];if(!pl.coinSkins.includes(b.key))pl.coinSkins.push(b.key);save();return send(res,200,{player:publicPlayer(pl),skins:pl.skins,coinSkins:pl.coinSkins})}
  }
  if(method==='GET'&&p==='/'){res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-cache'});return res.end(fs.readFileSync(path.join(ROOT,'VITIN7S_Cartoon3D_muitos_trens.html')))}
  return send(res,404,{error:'Não encontrado.'});
 }catch(e){console.error(e);return send(res,500,{error:'Erro interno do servidor.'})}
});
server.listen(PORT,()=>console.log(`VITIN7S API rodando na porta ${PORT}`));
