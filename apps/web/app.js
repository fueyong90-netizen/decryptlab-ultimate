'use strict';
// DecryptLab Ultimate — PWA client. Real local analysis for open formats,
// mirroring the C++ core. No file leaves the browser.

// ---------- ASCII logo ----------
const LOGO = String.raw`
      .d88888888888b.        ____  _     _   _
    .8888P""   ""Y8888b.    |  _ \| |   | | | |
   d88P   .--.   .--. Y88b  | | | | |   | | | |
   8888  (OO )   (OO ) 8888 | |_| | |___| |_| |
   Y88b   '--' _ '--'  d88P |____/|_____|\___/
    "Y88b.___( )___.d88P"      U L T I M A T E
       "Y8b "wwww" d8Y"
         by JORDAN HACKER`;
document.getElementById('asciiLogo').textContent = LOGO;

// ---------- navigation ----------
function show(view){
  document.querySelectorAll('.panel').forEach(p=>p.classList.toggle('active',p.dataset.panel===view));
  document.querySelectorAll('.sidebar a,.bottomnav a').forEach(a=>a.classList.toggle('active',a.dataset.view===view));
  window.scrollTo(0,0);
}
document.querySelectorAll('[data-view]').forEach(a=>a.addEventListener('click',()=>show(a.dataset.view)));
document.querySelectorAll('[data-go]').forEach(b=>b.addEventListener('click',()=>show(b.dataset.go)));

// ---------- helpers ----------
const SIGS = [
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
function matchMagic(bytes,sig){ if(bytes.length<sig.magic.length) return false;
  for(let i=0;i<sig.magic.length;i++) if(bytes[i]!==sig.magic[i]) return false; return true; }
function entropy(bytes){ if(!bytes.length) return 0; const f=new Array(256).fill(0);
  for(const b of bytes) f[b]++; let h=0; for(const c of f){ if(!c) continue; const p=c/bytes.length; h-=p*Math.log2(p);} return h; }
function ext(name){ const m=/\.([^.\/\\]+)$/.exec(name||''); return m?m[1].toLowerCase():''; }
async function sha256(buf){ const d=await crypto.subtle.digest('SHA-256',buf);
  return [...new Uint8Array(d)].map(b=>b.toString(16).padStart(2,'0')).join(''); }
function b64decode(s){ try{ return atob(s.replace(/-/g,'+').replace(/_/g,'/')); }catch(e){ return null; } }
function mask(s){ if(!s) return ''; if(s.length<=4) return '*'.repeat(s.length); return s.slice(0,3)+'*'.repeat(Math.min(8,s.length-3)); }
function esc(s){ return (s||'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }

const PROP_EXT={ehi:'HTTP Injector',hc:'HTTP Custom',npvs:'NapsternetV',hat:'HA Tunnel Plus'};

// ---------- file analysis ----------
async function analyzeFile(file){
  const buf=await file.arrayBuffer();
  const bytes=new Uint8Array(buf);
  const head=bytes.slice(0,65536);
  const e=ext(file.name);
  const hyps=SIGS.filter(s=>matchMagic(head,s)).map(s=>({...s,conf:s.ext.includes(e)?98:90}));
  const H=entropy(head);
  const hash=await sha256(buf);
  let out=`<div class="kv"><span>Fichier</span><b>${esc(file.name)}</b></div>`;
  out+=`<div class="kv"><span>Taille</span><b>${bytes.length} octets</b></div>`;
  out+=`<div class="kv"><span>SHA-256</span><b style="font-size:.7rem">${hash}</b></div>`;
  out+=`<div class="kv"><span>Entropie</span><b>${H.toFixed(3)} bits/octet</b></div>`;
  // text sniff
  const txt=new TextDecoder('utf-8',{fatal:false}).decode(head.slice(0,4096));
  if(PROP_EXT[e]){
    const enc=H>7.5;
    out+=`<div class="kv"><span>Format</span><b>${e.toUpperCase()} (propriétaire, ${PROP_EXT[e]})</b></div>`;
    out+=`<div class="result" style="border-color:var(--dred);margin-top:10px">`;
    out+=`<b class="red">État :</b> ${enc?'semble chiffré/obfusqué par l\'application d\'origine':'pas de signal de chiffrement fort'}<br><br>`;
    out+=`<b>Limitation :</b> DecryptLab identifie et documente ce format mais ne casse pas la protection posée par son auteur et n'extrait pas de clés/mots de passe. Le décodage exigerait l'algorithme et la clé du format, non déductibles du fichier seul.</div>`;
  } else if(hyps.length){
    const t=hyps.sort((a,b)=>b.conf-a.conf)[0];
    out+=`<div class="kv"><span>Meilleure hypothèse</span><b>${t.label} (${t.conf}%)</b></div>`;
    out+=`<div class="kv"><span>Catégorie</span><b>${t.cat}</b></div>`;
    if(!t.ext.includes(e)&&e) out+=`<p class="red">⚠ L'extension .${e} ne correspond pas au contenu détecté.</p>`;
    if(t.id==='zip') out+=`<p class="note">Archive ZIP : inspection de structure côté noyau C++ (lecture seule, anti zip-bomb).</p>`;
  } else if(/^\s*[\{\[]/.test(txt)) out+=`<div class="kv"><span>Format</span><b>JSON (texte)</b></div>`;
  else out+=`<div class="kv"><span>Format</span><b>${H>7.5?'inconnu / haute entropie':'texte / inconnu'}</b></div>`;
  out+=`<p class="note">Analyse 100% locale. Les octets ne quittent pas le navigateur.</p>`;
  document.getElementById('analyzeResult').innerHTML=out;
}
const dz=document.getElementById('dropZone'), fi=document.getElementById('fileInput');
document.getElementById('browseBtn').onclick=()=>fi.click();
fi.onchange=()=>fi.files[0]&&analyzeFile(fi.files[0]);
['dragover','dragenter'].forEach(ev=>dz.addEventListener(ev,e=>{e.preventDefault();dz.classList.add('drag')}));
['dragleave','drop'].forEach(ev=>dz.addEventListener(ev,e=>{e.preventDefault();dz.classList.remove('drag')}));
dz.addEventListener('drop',e=>{const f=e.dataTransfer.files[0]; if(f) analyzeFile(f);});

// ---------- VPN URI parsing ----------
function parseURI(uri){
  uri=uri.trim();
  const m=/^([a-z0-9]+):\/\/(.*)$/i.exec(uri); if(!m) return {error:'pas de schéma'};
  const scheme=m[1].toLowerCase(), rest=m[2];
  if(scheme==='vmess'){
    const js=b64decode(rest); if(!js) return {error:'vmess: base64 invalide'};
    let j; try{ j=JSON.parse(js);}catch(e){ return {error:'vmess: JSON invalide'}; }
    return {protocol:'vmess',address:j.add,port:+j.port,uuid:j.id,network:j.net||'tcp',
      security:j.tls||'none',path:j.path||'',host:j.host||'',sni:j.sni||'',tag:j.ps||''};
  }
  if(scheme==='vless'||scheme==='trojan'){
    const u=new URL(uri.replace(scheme+'://','http://'));
    const p={protocol:scheme,address:u.hostname,port:+u.port||443,tag:decodeURIComponent(u.hash.slice(1)),
      network:u.searchParams.get('type')||'tcp',security:u.searchParams.get('security')||(scheme==='trojan'?'tls':'none'),
      sni:u.searchParams.get('sni')||'',path:u.searchParams.get('path')||'',host:u.searchParams.get('host')||'',
      flow:u.searchParams.get('flow')||''};
    if(scheme==='vless') p.uuid=decodeURIComponent(u.username); else p.password=decodeURIComponent(u.username);
    return p;
  }
  if(scheme==='ss'){
    let body=rest, tag=''; const h=rest.indexOf('#'); if(h>=0){tag=decodeURIComponent(rest.slice(h+1));body=rest.slice(0,h);}
    const at=body.indexOf('@');
    if(at>=0){ const creds=b64decode(body.slice(0,at))||body.slice(0,at); const c=creds.indexOf(':');
      const hp=body.slice(at+1).split(':');
      return {protocol:'shadowsocks',method:creds.slice(0,c),password:creds.slice(c+1),address:hp[0],port:+hp[1],tag};
    } else { const dec=b64decode(body); if(!dec) return {error:'ss: base64 invalide'};
      const a2=dec.indexOf('@'); const creds=dec.slice(0,a2); const c=creds.indexOf(':'); const hp=dec.slice(a2+1).split(':');
      return {protocol:'shadowsocks',method:creds.slice(0,c),password:creds.slice(c+1),address:hp[0],port:+hp[1],tag};
    }
  }
  return {error:'schéma non supporté: '+scheme};
}
function parseWireguard(t){ const p={protocol:'wireguard',extra:{}};
  for(const line of t.split('\n')){ const s=line.trim(); if(!s||s[0]==='#'||s[0]==='[') continue;
    const i=s.indexOf('='); if(i<0) continue; const k=s.slice(0,i).trim().toLowerCase(), v=s.slice(i+1).trim();
    if(k==='privatekey')p.wg_private_key=v; else if(k==='publickey')p.wg_public_key=v;
    else if(k==='endpoint'){p.wg_endpoint=v;const c=v.lastIndexOf(':');p.address=v.slice(0,c);p.port=+v.slice(c+1);}
    else if(k==='address')p.address_local=v; } return p; }
function parseOpenVPN(t){ const p={protocol:'openvpn'};
  for(const line of t.split('\n')){ const s=line.trim(); if(!s||s[0]==='#') continue;
    const parts=s.split(/\s+/);
    if(parts[0]==='remote'){p.address=parts[1];p.port=+parts[2]||1194;}
    else if(parts[0]==='proto')p.network=parts[1]; else if(parts[0]==='cipher')p.method=parts[1]; }
  return p; }

function parseVPN(text){
  text=text.trim();
  if(text.includes('[Interface]')) return {fmt:'wireguard',profiles:[parseWireguard(text)]};
  if(/^[\{\[]/.test(text)&&text.includes('outbounds')){ try{ const j=JSON.parse(text);
    const profs=(j.outbounds||[]).filter(o=>o.settings&&(o.settings.vnext||o.settings.servers)).map(o=>{
      const s=o.settings.vnext?o.settings.vnext[0]:o.settings.servers[0];
      const u=s.users?s.users[0]:{};
      return {protocol:o.protocol,address:s.address,port:s.port,uuid:u.id,password:s.password,method:s.method,
        network:(o.streamSettings||{}).network||'tcp',security:(o.streamSettings||{}).security||'none',tag:o.tag||''};
    }); return {fmt:'v2ray-json',profiles:profs}; }catch(e){ return {fmt:'error',profiles:[],error:'JSON invalide'};} }
  if(/^(vmess|vless|trojan|ss|ssr):\/\//.test(text)){ const lines=text.split('\n').map(l=>l.trim()).filter(l=>l.includes('://'));
    return {fmt:'uri',profiles:lines.map(parseURI)}; }
  if(text.includes('remote ')||text.includes('client')) return {fmt:'ovpn',profiles:[parseOpenVPN(text)]};
  // subscription base64
  const dec=b64decode(text.replace(/\s/g,'')); if(dec&&dec.includes('://')){
    return {fmt:'subscription',profiles:dec.split('\n').map(l=>l.trim()).filter(l=>l.includes('://')).map(parseURI)}; }
  return {fmt:'unknown',profiles:[]};
}
function renderProfiles(res,reveal){
  if(!res.profiles.length) return `<p class="red">Aucun profil reconnu (format: ${res.fmt}).</p>`;
  let o=`<div class="kv"><span>Format source</span><b>${res.fmt}</b></div>`;
  res.profiles.forEach((p,i)=>{
    if(p.error){ o+=`<p class="red">#${i+1} ${esc(p.error)}</p>`; return; }
    const secret=reveal?(p.uuid||p.password||''):mask(p.uuid||p.password||'');
    o+=`<div class="result" style="margin-top:10px">`;
    o+=`<div class="kv"><span>Protocole</span><b>${esc(p.protocol)}</b></div>`;
    if(p.tag)o+=`<div class="kv"><span>Nom</span><b>${esc(p.tag)}</b></div>`;
    o+=`<div class="kv"><span>Serveur</span><b>${esc(p.address||'')}:${p.port||''}</b></div>`;
    if(p.network)o+=`<div class="kv"><span>Transport</span><b>${esc(p.network)} / ${esc(p.security||'')}</b></div>`;
    if(secret)o+=`<div class="kv"><span>${p.uuid?'UUID':'Password'}</span><b>${esc(secret)}</b></div>`;
    if(p.method)o+=`<div class="kv"><span>Méthode</span><b>${esc(p.method)}</b></div>`;
    o+=`</div>`;
  });
  return o;
}
document.getElementById('vpnParseBtn').onclick=()=>{
  const res=parseVPN(document.getElementById('vpnInput').value);
  const reveal=document.getElementById('revealChk').checked;
  document.getElementById('vpnResult').innerHTML=renderProfiles(res,reveal)
    +(reveal?'':'<p class="note">Secrets masqués. Cochez la case pour vos propres fichiers.</p>');
};

// ---------- security audit ----------
const WEAK=['rc4','rc4-md5','des','3des','aes-128-cfb','aes-256-cfb','bf-cfb','table'];
function audit(text){
  const f=[]; let score=100;
  const add=(sev,title,rec,pen)=>{f.push({sev,title,rec});score-=pen;};
  const res=parseVPN(text);
  res.profiles.forEach(p=>{
    if(p.security==='none'&&['vmess','vless','trojan'].includes(p.protocol)) add('high','Pas de chiffrement de transport (security=none)','Activez TLS/Reality.',25);
    if(p.method&&WEAK.includes(p.method.toLowerCase())) add('medium','Cipher faible/obsolète: '+p.method,'Préférez chacha20-ietf-poly1305 ou aes-256-gcm.',12);
  });
  if(/-----BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY-----/.test(text)) add('high','Clé privée en clair dans la config','Stockez les clés séparément (chmod 600).',25);
  if(/allowInsecure"?\s*[:=]\s*(true|1)/.test(text)) add('high','Validation du certificat désactivée','allowInsecure=false + certificat valide.',25);
  if(!f.length) add('info','Aucun problème évident détecté','Vérification heuristique, pas un audit complet.',0);
  return {findings:f,score:Math.max(0,score)};
}
document.getElementById('auditBtn').onclick=()=>{
  const r=audit(document.getElementById('auditInput').value);
  let o=`<div class="score">${r.score}/100</div>`;
  r.findings.forEach(x=>{ o+=`<p><span class="tag sev-${x.sev}">${x.sev}</span> <b>${esc(x.title)}</b><br><small class="note">→ ${esc(x.rec)}</small></p>`; });
  document.getElementById('auditResult').innerHTML=o;
};

// ---------- generator ----------
function uuidv4(){ const b=crypto.getRandomValues(new Uint8Array(16)); b[6]=(b[6]&0x0f)|0x40;b[8]=(b[8]&0x3f)|0x80;
  const h=[...b].map(x=>x.toString(16).padStart(2,'0')); return `${h[0]}${h[1]}${h[2]}${h[3]}-${h[4]}${h[5]}-${h[6]}${h[7]}-${h[8]}${h[9]}-${h[10]}${h[11]}${h[12]}${h[13]}${h[14]}${h[15]}`; }
function randpw(n=16){ const b=crypto.getRandomValues(new Uint8Array(n));
  return btoa(String.fromCharCode(...b)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }
function gen(){
  const proto=document.getElementById('genProto').value;
  const addr=document.getElementById('genAddr').value||'my.server.net';
  const port=+document.getElementById('genPort').value||443;
  const net=document.getElementById('genNet').value, sec=document.getElementById('genSec').value;
  const sni=document.getElementById('genSni').value||addr;
  const uuid=uuidv4(), pw=randpw();
  if(['vless','vmess','trojan','shadowsocks'].includes(proto)){
    const ob={tag:'dlu',protocol:proto,settings:{},streamSettings:{network:net,security:sec}};
    if(proto==='vmess'||proto==='vless') ob.settings.vnext=[{address:addr,port,users:[proto==='vmess'?{id:uuid,alterId:0,security:'auto'}:{id:uuid,encryption:'none'}]}];
    else ob.settings.servers=[{address:addr,port,password:pw,...(proto==='shadowsocks'?{method:'chacha20-ietf-poly1305'}:{})}];
    if(sec==='tls') ob.streamSettings.tlsSettings={serverName:sni,allowInsecure:false};
    if(net==='ws') ob.streamSettings.wsSettings={path:'/dlu',headers:{Host:sni}};
    const cfg={log:{loglevel:'warning'},inbounds:[{tag:'socks',port:10808,listen:'127.0.0.1',protocol:'socks',settings:{udp:true}}],
      outbounds:[ob,{tag:'direct',protocol:'freedom'}]};
    return {name:proto+'_client.json',content:JSON.stringify(cfg,null,2)};
  }
  if(proto==='wireguard') return {name:'wg0.conf',content:
`[Interface]\nPrivateKey = ${randpw(32)}\nAddress = 10.66.66.2/32\nDNS = 1.1.1.1\n\n[Peer]\nPublicKey = REPLACE_WITH_SERVER_PUBLIC_KEY\nEndpoint = ${addr}:${port===443?51820:port}\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n`};
  if(proto==='openvpn') return {name:'client.ovpn',content:
`client\ndev tun\nproto ${net==='tcp'?'tcp':'udp'}\nremote ${addr} ${port===443?1194:port}\nresolv-retry infinite\nnobind\npersist-key\npersist-tun\nremote-cert-tls server\ncipher AES-256-GCM\nauth SHA256\nverb 3\n\n# Ajoutez vos blocs <ca> <cert> <key> depuis votre PKI.\n`};
  if(proto==='ssh') return {name:'ssh_tunnel.sh',content:
`#!/usr/bin/env bash\n# DecryptLab Ultimate - SSH SOCKS tunnel (serveur que vous administrez)\nset -euo pipefail\nSERVER="${addr}"\nPORT="${port===443?22:port}"\nUSER="user"\nssh -N -D "127.0.0.1:1080" -p "$PORT" -o ServerAliveInterval=30 "$USER@$SERVER"\n# Proxy: socks5://127.0.0.1:1080\n`};
  if(proto==='slowdns') return {name:'slowdns_client.sh',content:
`#!/usr/bin/env bash\n# DecryptLab Ultimate - SlowDNS (dnstt) template (NS que vous déléguez)\nset -euo pipefail\nNS="ns.${addr}"\nPUBKEY="REPLACE_WITH_SERVER_PUBLIC_KEY"\nRESOLVER="8.8.8.8:53"\ndnstt-client -udp "$RESOLVER" -pubkey "$PUBKEY" "$NS" "127.0.0.1:2222"\n`};
  if(proto==='udp') return {name:'udp_custom.json',content:
JSON.stringify({listen:':36712',stream_buffer:33554432,receive_buffer:83886080,auth:{mode:'passwords',passwords:[pw]},ignore_list:[]},null,2)};
  return {name:'config.txt',content:'# protocole non supporté'};
}
let lastGen={name:'config.txt',content:''};
document.getElementById('genBtn').onclick=()=>{ lastGen=gen(); document.getElementById('genOutput').textContent=lastGen.content; };
document.getElementById('genCopy').onclick=()=>{ if(lastGen.content) navigator.clipboard.writeText(lastGen.content); };
document.getElementById('genDownload').onclick=()=>{ if(!lastGen.content) return;
  const a=document.createElement('a'); a.href=URL.createObjectURL(new Blob([lastGen.content])); a.download=lastGen.name; a.click(); };

// ---------- PWA ----------
if('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(()=>{});
