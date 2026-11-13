'use strict';
/* DecryptLab Ultimate — PWA client (by JORDAN HACKER).
   Real local analysis for open formats. No file leaves the browser. */

const LOGO = String.raw`
        .d8888888888b.          _____  _      _    _
      .8888P""    ""Y888b.     |  __ \| |    | |  | |
     d88P   .--.    .--. Y88b  | |  | | |    | |  | |
     888   (0xF)    (0x1) 888  | |  | | |    | |  | |
     Y88b   '--'  __  '--' d88P | |__| | |____| |__| |
      "Y88b.     (==)    .d88P" |_____/|______\____/
        "Y8b._   wwww  _.d8Y"
          "Y888b.__.d888Y"      U L T I M A T E
             "Y8888888Y"
             by JORDAN HACKER`;
document.getElementById('asciiLogo').textContent = LOGO;

/* ---------- settings ---------- */
const CFG = JSON.parse(localStorage.getItem('dlu_cfg') || '{}');
function saveCfg(){ localStorage.setItem('dlu_cfg', JSON.stringify(CFG)); }
if (CFG.anim === false) document.body.classList.add('noanim');

/* ---------- navigation ---------- */
function show(view){
  document.querySelectorAll('.panel').forEach(p=>p.classList.toggle('active',p.dataset.panel===view));
  document.querySelectorAll('.sidebar a,.bottomnav a').forEach(a=>a.classList.toggle('active',a.dataset.view===view));
  window.scrollTo(0,0);
}
document.querySelectorAll('[data-view]').forEach(a=>a.addEventListener('click',()=>show(a.dataset.view)));
document.querySelectorAll('[data-go]').forEach(b=>b.addEventListener('click',()=>show(b.dataset.go)));
document.getElementById('menuBtn').onclick=()=>{ const s=document.getElementById('sidebar');
  s.style.display = (s.style.display==='flex')?'none':'flex'; };

/* ---------- helpers ---------- */
const SIGS=[
  {id:'zip',label:'ZIP archive',cat:'archive',magic:[0x50,0x4B,0x03,0x04],ext:['zip','docx','xlsx','pptx','apk','jar']},
  {id:'rar',label:'RAR archive',cat:'archive',magic:[0x52,0x61,0x72,0x21],ext:['rar']},
  {id:'7z',label:'7-Zip',cat:'archive',magic:[0x37,0x7A,0xBC,0xAF],ext:['7z']},
  {id:'gzip',label:'GZIP',cat:'archive',magic:[0x1F,0x8B],ext:['gz','tgz']},
  {id:'pdf',label:'PDF document',cat:'document',magic:[0x25,0x50,0x44,0x46],ext:['pdf']},
  {id:'png',label:'PNG image',cat:'image',magic:[0x89,0x50,0x4E,0x47],ext:['png']},
  {id:'jpg',label:'JPEG image',cat:'image',magic:[0xFF,0xD8,0xFF],ext:['jpg','jpeg']},
  {id:'elf',label:'ELF binary',cat:'binary',magic:[0x7F,0x45,0x4C,0x46],ext:['elf','so','bin']},
  {id:'pe',label:'PE/EXE',cat:'binary',magic:[0x4D,0x5A],ext:['exe','dll']},
  {id:'sqlite',label:'SQLite DB',cat:'database',magic:[0x53,0x51,0x4C,0x69,0x74,0x65],ext:['db','sqlite']},
  {id:'pem',label:'PEM block',cat:'crypto',magic:[0x2D,0x2D,0x2D,0x2D,0x2D,0x42,0x45,0x47,0x49,0x4E],ext:['pem','crt','key']},
];
const PROP_EXT={ehi:'HTTP Injector',hc:'HTTP Custom',npvs:'NapsternetV',hat:'HA Tunnel Plus'};
function matchMagic(b,s){ if(b.length<s.magic.length) return false; for(let i=0;i<s.magic.length;i++) if(b[i]!==s.magic[i]) return false; return true; }
function entropy(b){ if(!b.length) return 0; const f=new Array(256).fill(0); for(const x of b) f[x]++; let h=0;
  for(const c of f){ if(!c) continue; const p=c/b.length; h-=p*Math.log2(p);} return h; }
function ext(n){ const m=/\.([^.\/\\]+)$/.exec(n||''); return m?m[1].toLowerCase():''; }
async function sha256(buf){ const d=await crypto.subtle.digest('SHA-256',buf); return hex(new Uint8Array(d)); }
async function sha1(buf){ const d=await crypto.subtle.digest('SHA-1',buf); return hex(new Uint8Array(d)); }
function hex(u8){ return [...u8].map(b=>b.toString(16).padStart(2,'0')).join(''); }
function b64decode(s){ try{ return atob(s.replace(/-/g,'+').replace(/_/g,'/')); }catch(e){ return null; } }
function mask(s){ if(!s) return ''; if(s.length<=4) return '*'.repeat(s.length); return s.slice(0,3)+'*'.repeat(Math.min(8,s.length-3)); }
function esc(s){ return (s||'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }
function kv(k,v){ return `<div class="kv"><span>${esc(k)}</span><b>${esc(String(v))}</b></div>`; }

/* ---------- reports history ---------- */
function logReport(entry){ const h=JSON.parse(localStorage.getItem('dlu_reports')||'[]');
  h.unshift({t:new Date().toISOString(),...entry}); localStorage.setItem('dlu_reports',JSON.stringify(h.slice(0,100))); }

/* ========== ANALYSE ========== */
async function analyzeFile(file){
  const buf=await file.arrayBuffer(), bytes=new Uint8Array(buf), head=bytes.slice(0,65536), e=ext(file.name);
  const hyps=SIGS.filter(s=>matchMagic(head,s)).map(s=>({...s,conf:s.ext.includes(e)?98:90}));
  const H=entropy(head), hash=await sha256(buf);
  let o=kv('Fichier',file.name)+kv('Taille',bytes.length+' octets')
       +`<div class="kv"><span>SHA-256</span><b style="font-size:.7rem">${hash}</b></div>`
       +kv('Entropie',H.toFixed(3)+' bits/octet');
  const txt=new TextDecoder('utf-8',{fatal:false}).decode(head.slice(0,4096));
  let verdict='';
  if(PROP_EXT[e]){ const enc=H>7.5;
    o+=kv('Format',e.toUpperCase()+' (propriétaire, '+PROP_EXT[e]+')');
    o+=`<div class="result" style="border-color:var(--dred)"><b class="red">État :</b> ${enc?'semble chiffré/obfusqué par l\'application d\'origine':'pas de signal de chiffrement fort'}<br><br><b>Limitation :</b> DecryptLab identifie et documente ce format mais ne casse pas la protection posée par son auteur et n'extrait pas de clés/mots de passe. Le décodage exigerait l'algorithme et la clé du format, non déductibles du fichier seul.</div>`;
    verdict=e.toUpperCase()+' (propriétaire)';
  } else if(hyps.length){ const t=hyps.sort((a,b)=>b.conf-a.conf)[0];
    o+=kv('Meilleure hypothèse',t.label+' ('+t.conf+'%)')+kv('Catégorie',t.cat);
    if(!t.ext.includes(e)&&e) o+=`<p class="red">⚠ L'extension .${esc(e)} ne correspond pas au contenu détecté.</p>`;
    verdict=t.label;
  } else if(/^\s*[\{\[]/.test(txt)){ o+=kv('Format','JSON (texte)'); verdict='JSON'; }
  else { verdict=H>7.5?'inconnu / haute entropie':'texte / inconnu'; o+=kv('Format',verdict); }
  o+=`<p class="note">Analyse 100% locale.</p>`;
  document.getElementById('analyzeResult').innerHTML=o;
  logReport({kind:'analyse',file:file.name,size:bytes.length,sha256:hash,verdict});
}
function wireDrop(zoneId,inputId,cb){
  const dz=document.getElementById(zoneId),fi=document.getElementById(inputId);
  if(!dz||!fi) return;
  fi.onchange=()=>fi.files[0]&&cb(fi.files[0]);
  ['dragover','dragenter'].forEach(ev=>dz.addEventListener(ev,e=>{e.preventDefault();dz.classList.add('drag')}));
  ['dragleave','drop'].forEach(ev=>dz.addEventListener(ev,e=>{e.preventDefault();dz.classList.remove('drag')}));
  dz.addEventListener('drop',e=>{const f=e.dataTransfer.files[0]; if(f) cb(f);});
}
wireDrop('dropZone','fileInput',analyzeFile);
document.getElementById('browseBtn').onclick=()=>document.getElementById('fileInput').click();

/* ========== ARCHIVES (ZIP central directory, read-only) ========== */
function inspectZip(bytes){
  const dv=new DataView(bytes.buffer);
  const n=bytes.length;
  // find EOCD 0x06054b50
  let eocd=-1; for(let i=n-22;i>=Math.max(0,n-66000);i--){ if(dv.getUint32(i,true)===0x06054b50){eocd=i;break;} }
  if(eocd<0) return {error:'EOCD introuvable (pas un ZIP ou tronqué)'};
  const total=dv.getUint16(eocd+10,true), cdoff=dv.getUint32(eocd+16,true);
  const entries=[]; let p=cdoff,enc=false,bomb=false,totun=0,count=0;
  while(p+46<=n && dv.getUint32(p,true)===0x02014b50){
    const flags=dv.getUint16(p+8,true),method=dv.getUint16(p+10,true);
    const csize=dv.getUint32(p+20,true),usize=dv.getUint32(p+24,true);
    const nlen=dv.getUint16(p+28,true),elen=dv.getUint16(p+30,true),clen=dv.getUint16(p+32,true);
    const name=new TextDecoder().decode(bytes.slice(p+46,p+46+nlen));
    const e=(flags&1)!==0; if(e) enc=true; totun+=usize;
    if(csize>0 && usize/csize>1000) bomb=true;
    entries.push({name,usize,method,enc});
    p+=46+nlen+elen+clen; if(++count>100000){bomb=true;break;}
  }
  return {total,entries,enc,bomb,totun};
}
async function handleZip(file){
  const bytes=new Uint8Array(await file.arrayBuffer());
  const r=inspectZip(bytes);
  const el=document.getElementById('zipResult');
  if(r.error){ el.innerHTML=`<p class="red">${esc(r.error)}</p>`; return; }
  let o=kv('Archive',file.name)+kv('Entrées',r.entries.length)
    +kv('Entrées chiffrées',r.enc?'OUI (mot de passe requis — non récupéré ici)':'non')
    +kv('Zip-bomb suspectée',r.bomb?'⚠ OUI — ne pas extraire automatiquement':'non')
    +kv('Taille décompressée',r.totun+' octets');
  o+='<div class="result">';
  r.entries.slice(0,60).forEach(e=>{ o+=`<div class="kv"><span>${e.enc?'🔒 ':''}${esc(e.name)}</span><b>${e.usize} o</b></div>`; });
  if(r.entries.length>60) o+=`<p class="note">… ${r.entries.length-60} de plus</p>`;
  o+='</div>';
  if(r.enc) o+=`<p class="note">Les entrées chiffrées nécessitent VOTRE mot de passe. DecryptLab ne casse pas les mots de passe de tiers.</p>`;
  el.innerHTML=o;
  logReport({kind:'archive',file:file.name,entries:r.entries.length,encrypted:r.enc});
}
wireDrop('zipDrop','zipFile',handleZip);
document.getElementById('zipBrowse').onclick=()=>document.getElementById('zipFile').click();

/* ========== DÉCRYPTAGE / DÉCODAGE ========== */
document.getElementById('decBrowse').onclick=()=>document.getElementById('decFile').click();
document.getElementById('decFile').onchange=async e=>{ const f=e.target.files[0]; if(!f) return;
  const t=await f.text(); document.getElementById('decInput').value=t.slice(0,20000); };
document.getElementById('decBtn').onclick=async()=>{
  const inp=document.getElementById('decInput').value.trim();
  const mode=document.getElementById('decMode').value, key=document.getElementById('decKey').value;
  const el=document.getElementById('decResult');
  if(!inp){ el.innerHTML='<p class="red">Entrée vide.</p>'; return; }
  try{
    if(mode==='base64'||(mode==='auto'&&/^[A-Za-z0-9+/=_-]+$/.test(inp.replace(/\s/g,'')))){
      const d=b64decode(inp.replace(/\s/g,'')); if(d===null) throw 0;
      el.innerHTML=`<b>Base64 → texte :</b><div class="code">${esc(d)}</div>`; return;
    }
    if(mode==='hex'){ const clean=inp.replace(/[^0-9a-fA-F]/g,''); let s='';
      for(let i=0;i<clean.length-1;i+=2) s+=String.fromCharCode(parseInt(clean.substr(i,2),16));
      el.innerHTML=`<b>Hex → texte :</b><div class="code">${esc(s)}</div>`; return;
    }
    if(mode==='aes'){
      if(!key){ el.innerHTML='<p class="red">Fournissez votre clé/mot de passe (pour VOS fichiers).</p>'; return; }
      el.innerHTML=`<p class="note">Le déchiffrement AES-GCM exige la clé, l'IV et le tag d'authentification exactement tels que vous les avez chiffrés. Fournissez un conteneur au format IV(12o)||ciphertext||tag et la clé en base64/hex. Cette opération ne s'applique qu'à VOS données ; DecryptLab ne devine pas de clé.</p>`;
      return;
    }
    // auto fallback: proprietary/doc note
    el.innerHTML=`<p>Entrée non reconnue comme Base64/hex. Si c'est un format propriétaire chiffré, il est <b>documenté</b> mais non cassé. Utilisez l'onglet <b>Analyse</b> pour un diagnostic complet.</p>`;
  }catch(e){ el.innerHTML='<p class="red">Décodage impossible (entrée invalide).</p>'; }
};

/* ========== RÉCUPÉRATION (assistant honnête) ========== */
const REC={
  zip:["Vérifiez vos gestionnaires de mots de passe et notes pour le mot de passe de l'archive.",
       "Cherchez une copie non protégée dans vos sauvegardes / corbeille / historique cloud.",
       "Si c'est VOTRE archive, utilisez un outil local avec le mot de passe que vous connaissez.",
       "DecryptLab n'effectue pas de cassage de mot de passe sur des archives de tiers."],
  doc:["Cherchez la clé/mot de passe d'origine (gestionnaire, e-mail d'envoi, propriétaire du document).",
       "Vérifiez les versions antérieures non chiffrées (historique cloud, sauvegardes).",
       "Pour un PDF/Office protégé par VOUS, rouvrez-le avec le mot de passe connu.",
       "Aucune récupération de secret appartenant à autrui n'est effectuée."],
  vpn:["Les .ehi/.hc/.npvs/.hat sont chiffrés par leur auteur : contenu non extractible sans sa clé.",
       "Demandez le fichier d'origine non protégé à la personne qui l'a créé.",
       "Utilisez l'onglet Analyse pour obtenir la structure, l'entropie et la limitation exacte.",
       "DecryptLab documente ces formats, il ne les casse pas."],
  deleted:["Cessez d'écrire sur le support concerné pour maximiser les chances.",
       "Utilisez un outil de carving (photorec/testdisk) sur une COPIE image du support.",
       "Restaurez depuis une sauvegarde si disponible (souvent le plus fiable).",
       "La récupération dépend du système de fichiers et de l'écrasement des blocs."],
  corrupt:["Faites une copie avant toute tentative (ne jamais travailler sur l'original).",
       "Vérifiez/réparez les en-têtes selon le format (ex. zip -FF pour un ZIP).",
       "Comparez avec une version saine si vous en avez une.",
       "Une récupération partielle est parfois le maximum atteignable."]
};
document.getElementById('recBtn').onclick=()=>{
  const t=document.getElementById('recType').value;
  const steps=REC[t]||[];
  let o='<ol style="margin:0;padding-left:20px;line-height:1.9">';
  steps.forEach(s=>o+=`<li>${esc(s)}</li>`); o+='</ol>';
  document.getElementById('recResult').innerHTML=o;
};

/* ========== VPN ========== */
function parseURI(uri){
  uri=uri.trim();
  const m=/^([a-z0-9]+):\/\/(.*)$/i.exec(uri); if(!m) return {error:'pas de schéma'};
  const scheme=m[1].toLowerCase(), rest=m[2];
  if(scheme==='vmess'){ const js=b64decode(rest); if(!js) return {error:'vmess: base64 invalide'};
    let j; try{ j=JSON.parse(js);}catch(e){ return {error:'vmess: JSON invalide'}; }
    return {protocol:'vmess',address:j.add,port:+j.port,uuid:j.id,network:j.net||'tcp',security:j.tls||'none',path:j.path||'',host:j.host||'',sni:j.sni||'',tag:j.ps||''}; }
  if(scheme==='vless'||scheme==='trojan'){ const u=new URL(uri.replace(scheme+'://','http://'));
    const p={protocol:scheme,address:u.hostname,port:+u.port||443,tag:decodeURIComponent(u.hash.slice(1)),
      network:u.searchParams.get('type')||'tcp',security:u.searchParams.get('security')||(scheme==='trojan'?'tls':'none'),
      sni:u.searchParams.get('sni')||'',path:u.searchParams.get('path')||'',host:u.searchParams.get('host')||''};
    if(scheme==='vless') p.uuid=decodeURIComponent(u.username); else p.password=decodeURIComponent(u.username); return p; }
  if(scheme==='ss'){ let body=rest,tag=''; const h=rest.indexOf('#'); if(h>=0){tag=decodeURIComponent(rest.slice(h+1));body=rest.slice(0,h);}
    const at=body.indexOf('@');
    if(at>=0){ const creds=b64decode(body.slice(0,at))||body.slice(0,at); const c=creds.indexOf(':'); const hp=body.slice(at+1).split(':');
      return {protocol:'shadowsocks',method:creds.slice(0,c),password:creds.slice(c+1),address:hp[0],port:+hp[1],tag}; }
    const dec=b64decode(body); if(!dec) return {error:'ss: base64 invalide'};
    const a2=dec.indexOf('@'); const creds=dec.slice(0,a2); const c=creds.indexOf(':'); const hp=dec.slice(a2+1).split(':');
    return {protocol:'shadowsocks',method:creds.slice(0,c),password:creds.slice(c+1),address:hp[0],port:+hp[1],tag}; }
  return {error:'schéma non supporté: '+scheme};
}
function parseVPN(text){ text=text.trim();
  if(text.includes('[Interface]')){ const p={protocol:'wireguard'};
    for(const l of text.split('\n')){ const s=l.trim(); if(!s||s[0]==='#'||s[0]==='[') continue;
      const i=s.indexOf('='); if(i<0) continue; const k=s.slice(0,i).trim().toLowerCase(),v=s.slice(i+1).trim();
      if(k==='privatekey')p.password=v; else if(k==='endpoint'){const c=v.lastIndexOf(':');p.address=v.slice(0,c);p.port=+v.slice(c+1);} }
    return {fmt:'wireguard',profiles:[p]}; }
  if(/^[\{\[]/.test(text)&&text.includes('outbounds')){ try{ const j=JSON.parse(text);
    const profs=(j.outbounds||[]).filter(o=>o.settings&&(o.settings.vnext||o.settings.servers)).map(o=>{
      const s=o.settings.vnext?o.settings.vnext[0]:o.settings.servers[0]; const u=s.users?s.users[0]:{};
      return {protocol:o.protocol,address:s.address,port:s.port,uuid:u.id,password:s.password,method:s.method,
        network:(o.streamSettings||{}).network||'tcp',security:(o.streamSettings||{}).security||'none',tag:o.tag||''}; });
    return {fmt:'v2ray-json',profiles:profs}; }catch(e){ return {fmt:'error',profiles:[],error:'JSON invalide'};} }
  if(/^(vmess|vless|trojan|ss):\/\//.test(text)) return {fmt:'uri',profiles:text.split('\n').map(l=>l.trim()).filter(l=>l.includes('://')).map(parseURI)};
  if(text.includes('remote ')||text.includes('client')){ const p={protocol:'openvpn'};
    for(const l of text.split('\n')){ const s=l.trim().split(/\s+/);
      if(s[0]==='remote'){p.address=s[1];p.port=+s[2]||1194;} else if(s[0]==='cipher')p.method=s[1]; }
    return {fmt:'ovpn',profiles:[p]}; }
  const dec=b64decode(text.replace(/\s/g,'')); if(dec&&dec.includes('://')) return {fmt:'subscription',profiles:dec.split('\n').map(l=>l.trim()).filter(l=>l.includes('://')).map(parseURI)};
  return {fmt:'unknown',profiles:[]};
}
function renderProfiles(res,reveal){
  if(!res.profiles.length) return `<p class="red">Aucun profil reconnu (format: ${esc(res.fmt)}).</p>`;
  let o=kv('Format source',res.fmt);
  res.profiles.forEach((p,i)=>{ if(p.error){ o+=`<p class="red">#${i+1} ${esc(p.error)}</p>`; return; }
    const sec=reveal?(p.uuid||p.password||''):mask(p.uuid||p.password||'');
    o+='<div class="result">'+kv('Protocole',p.protocol);
    if(p.tag)o+=kv('Nom',p.tag); o+=kv('Serveur',(p.address||'')+':'+(p.port||''));
    if(p.network)o+=kv('Transport',(p.network)+' / '+(p.security||''));
    if(sec)o+=kv(p.uuid?'UUID':'Password',sec); if(p.method)o+=kv('Méthode',p.method); o+='</div>'; });
  return o;
}
document.getElementById('vpnParseBtn').onclick=()=>{
  const res=parseVPN(document.getElementById('vpnInput').value);
  const reveal=document.getElementById('revealChk').checked||CFG.reveal;
  document.getElementById('vpnResult').innerHTML=renderProfiles(res,reveal)+(reveal?'':'<p class="note">Secrets masqués.</p>');
  logReport({kind:'vpn',format:res.fmt,profiles:res.profiles.length});
};
const WEAK=['rc4','rc4-md5','des','3des','aes-128-cfb','aes-256-cfb','bf-cfb','table'];
document.getElementById('vpnAuditBtn').onclick=()=>{
  const text=document.getElementById('vpnInput').value; const f=[]; let score=100;
  const add=(sev,title,rec,pen)=>{f.push({sev,title,rec});score-=pen;};
  const res=parseVPN(text);
  res.profiles.forEach(p=>{ if(p.security==='none'&&['vmess','vless','trojan'].includes(p.protocol)) add('high','Pas de chiffrement de transport (security=none)','Activez TLS/Reality.',25);
    if(p.method&&WEAK.includes((p.method||'').toLowerCase())) add('medium','Cipher faible: '+p.method,'Préférez chacha20-ietf-poly1305 / aes-256-gcm.',12); });
  if(/-----BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY-----/.test(text)) add('high','Clé privée en clair','Stockez les clés séparément (chmod 600).',25);
  if(/allowInsecure"?\s*[:=]\s*(true|1)/.test(text)) add('high','Validation du certificat désactivée','allowInsecure=false + certificat valide.',25);
  if(!f.length) add('info','Aucun problème évident','Vérification heuristique.',0);
  let o=`<div class="score">${Math.max(0,score)}/100</div>`;
  f.forEach(x=>o+=`<p><span class="tag sev-${x.sev}">${x.sev}</span> <b>${esc(x.title)}</b><br><small class="note">→ ${esc(x.rec)}</small></p>`);
  document.getElementById('vpnResult').innerHTML=o;
};

/* ========== OUTILS : tabs ========== */
document.querySelectorAll('.tab').forEach(t=>t.onclick=()=>{
  document.querySelectorAll('.tab').forEach(x=>x.classList.toggle('active',x===t));
  document.querySelectorAll('.tabpanel').forEach(p=>p.classList.toggle('active',p.dataset.tabPanel===t.dataset.tab));
});
/* generator */
function uuidv4(){ const b=crypto.getRandomValues(new Uint8Array(16)); b[6]=(b[6]&0x0f)|0x40;b[8]=(b[8]&0x3f)|0x80;
  const h=[...b].map(x=>x.toString(16).padStart(2,'0')); return `${h[0]}${h[1]}${h[2]}${h[3]}-${h[4]}${h[5]}-${h[6]}${h[7]}-${h[8]}${h[9]}-${h[10]}${h[11]}${h[12]}${h[13]}${h[14]}${h[15]}`; }
function randpw(n=16){ const b=crypto.getRandomValues(new Uint8Array(n)); return btoa(String.fromCharCode(...b)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }
function gen(){
  const proto=document.getElementById('genProto').value, addr=document.getElementById('genAddr').value||'my.server.net';
  const port=+document.getElementById('genPort').value||443, net=document.getElementById('genNet').value, sec=document.getElementById('genSec').value;
  const sni=document.getElementById('genSni').value||addr, uuid=uuidv4(), pw=randpw();
  if(['vless','vmess','trojan','shadowsocks'].includes(proto)){
    const ob={tag:'dlu',protocol:proto,settings:{},streamSettings:{network:net,security:sec}};
    if(proto==='vmess'||proto==='vless') ob.settings.vnext=[{address:addr,port,users:[proto==='vmess'?{id:uuid,alterId:0,security:'auto'}:{id:uuid,encryption:'none'}]}];
    else ob.settings.servers=[{address:addr,port,password:pw,...(proto==='shadowsocks'?{method:'chacha20-ietf-poly1305'}:{})}];
    if(sec==='tls') ob.streamSettings.tlsSettings={serverName:sni,allowInsecure:false};
    if(net==='ws') ob.streamSettings.wsSettings={path:'/dlu',headers:{Host:sni}};
    return {name:proto+'_client.json',content:JSON.stringify({log:{loglevel:'warning'},inbounds:[{tag:'socks',port:10808,listen:'127.0.0.1',protocol:'socks',settings:{udp:true}}],outbounds:[ob,{tag:'direct',protocol:'freedom'}]},null,2)};
  }
  if(proto==='wireguard') return {name:'wg0.conf',content:`[Interface]\nPrivateKey = ${randpw(32)}\nAddress = 10.66.66.2/32\nDNS = 1.1.1.1\n\n[Peer]\nPublicKey = REPLACE_WITH_SERVER_PUBLIC_KEY\nEndpoint = ${addr}:${port===443?51820:port}\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n`};
  if(proto==='openvpn') return {name:'client.ovpn',content:`client\ndev tun\nproto ${net==='tcp'?'tcp':'udp'}\nremote ${addr} ${port===443?1194:port}\nresolv-retry infinite\nnobind\npersist-key\npersist-tun\nremote-cert-tls server\ncipher AES-256-GCM\nauth SHA256\nverb 3\n\n# Ajoutez vos blocs <ca> <cert> <key>.\n`};
  if(proto==='ssh') return {name:'ssh_tunnel.sh',content:`#!/usr/bin/env bash\nset -euo pipefail\nSERVER="${addr}"; PORT="${port===443?22:port}"; USER="user"\nssh -N -D "127.0.0.1:1080" -p "$PORT" -o ServerAliveInterval=30 "$USER@$SERVER"\n# socks5://127.0.0.1:1080\n`};
  if(proto==='slowdns') return {name:'slowdns_client.sh',content:`#!/usr/bin/env bash\nset -euo pipefail\nNS="ns.${addr}"; PUBKEY="REPLACE"; RESOLVER="8.8.8.8:53"\ndnstt-client -udp "$RESOLVER" -pubkey "$PUBKEY" "$NS" "127.0.0.1:2222"\n`};
  if(proto==='udp') return {name:'udp_custom.json',content:JSON.stringify({listen:':36712',stream_buffer:33554432,receive_buffer:83886080,auth:{mode:'passwords',passwords:[pw]},ignore_list:[]},null,2)};
  return {name:'config.txt',content:'# non supporté'};
}
let lastGen={name:'config.txt',content:''};
document.getElementById('genBtn').onclick=()=>{ lastGen=gen(); document.getElementById('genOutput').textContent=lastGen.content; };
document.getElementById('genCopy').onclick=()=>lastGen.content&&navigator.clipboard.writeText(lastGen.content);
document.getElementById('genDownload').onclick=()=>{ if(!lastGen.content) return; const a=document.createElement('a');
  a.href=URL.createObjectURL(new Blob([lastGen.content])); a.download=lastGen.name; a.click(); };
/* hash */
document.getElementById('hashBrowse').onclick=()=>document.getElementById('hashFile').click();
document.getElementById('hashFile').onchange=async e=>{ const f=e.target.files[0]; if(!f) return;
  const buf=await f.arrayBuffer();
  document.getElementById('hashResult').innerHTML=kv('Fichier',f.name)+kv('SHA-256',await sha256(buf))+kv('SHA-1',await sha1(buf)); };
document.getElementById('hashBtn').onclick=async()=>{ const t=document.getElementById('hashText').value;
  if(!t) return; const buf=new TextEncoder().encode(t);
  document.getElementById('hashResult').innerHTML=kv('SHA-256',await sha256(buf.buffer))+kv('SHA-1',await sha1(buf.buffer)); };
/* base64 */
document.getElementById('b64Enc').onclick=()=>{ const t=document.getElementById('b64Input').value;
  document.getElementById('b64Output').textContent=btoa(unescape(encodeURIComponent(t))); };
document.getElementById('b64Dec').onclick=()=>{ const t=document.getElementById('b64Input').value.replace(/\s/g,'');
  const d=b64decode(t); document.getElementById('b64Output').textContent=d===null?'(base64 invalide)':d; };
/* entropy */
document.getElementById('entBrowse').onclick=()=>document.getElementById('entFile').click();
document.getElementById('entFile').onchange=async e=>{ const f=e.target.files[0]; if(!f) return;
  const bytes=new Uint8Array(await f.arrayBuffer()); const H=entropy(bytes.slice(0,1<<20));
  let q=H<1?'très faible':H<4?'faible (texte)':H<6.5?'moyenne':H<7.5?'haute (compressé OU encodé)':'très haute (compressé/chiffré/aléatoire)';
  document.getElementById('entResult').innerHTML=kv('Fichier',f.name)+kv('Entropie',H.toFixed(4)+' bits/octet')+kv('Interprétation',q)+'<p class="note">Une entropie haute ne prouve pas le chiffrement.</p>'; };

/* ========== RAPPORTS ========== */
function renderReports(){ const h=JSON.parse(localStorage.getItem('dlu_reports')||'[]'); const el=document.getElementById('repList');
  if(!h.length){ el.innerHTML='<p class="note">Aucun rapport pour l\'instant.</p>'; return; }
  el.innerHTML=h.map(r=>`<div class="kv"><span>${new Date(r.t).toLocaleString()} · ${esc(r.kind)}</span><b>${esc(r.file||r.format||'')} ${esc(r.verdict||'')}</b></div>`).join(''); }
document.getElementById('repExport').onclick=()=>{ const h=localStorage.getItem('dlu_reports')||'[]'; const a=document.createElement('a');
  a.href=URL.createObjectURL(new Blob([h],{type:'application/json'})); a.download='dlu_rapports.json'; a.click(); };
document.getElementById('repClear').onclick=()=>{ localStorage.removeItem('dlu_reports'); renderReports(); };

/* ========== PARAMÈTRES ========== */
document.getElementById('setApi').value=CFG.api||'';
document.getElementById('setReveal').checked=!!CFG.reveal;
document.getElementById('setAnim').checked=CFG.anim!==false;
document.getElementById('setSave').onclick=()=>{ CFG.api=document.getElementById('setApi').value.trim();
  CFG.reveal=document.getElementById('setReveal').checked; CFG.anim=document.getElementById('setAnim').checked;
  saveCfg(); document.body.classList.toggle('noanim',!CFG.anim);
  document.getElementById('setStatus').textContent='Enregistré ✓'; setTimeout(()=>document.getElementById('setStatus').textContent='',2000); };

/* refresh reports when navigating */
document.querySelectorAll('[data-view="rapports"]').forEach(a=>a.addEventListener('click',renderReports));

/* ========== PWA ========== */
if('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(()=>{});
