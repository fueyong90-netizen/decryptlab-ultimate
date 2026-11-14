'use strict';
/* DecryptLab Ultimate — VPN Studio, Binary Analyzer, Crypto, Comparison.
   Reuses helpers from app.js (parseVPN, esc, kv, entropy). No external deps. */

/* ---------- small local helpers ---------- */
function $(id){ return document.getElementById(id); }
function uuid4(){ const b=crypto.getRandomValues(new Uint8Array(16)); b[6]=(b[6]&0x0f)|0x40;b[8]=(b[8]&0x3f)|0x80;
  const h=[...b].map(x=>x.toString(16).padStart(2,'0')); return `${h[0]}${h[1]}${h[2]}${h[3]}-${h[4]}${h[5]}-${h[6]}${h[7]}-${h[8]}${h[9]}-${h[10]}${h[11]}${h[12]}${h[13]}${h[14]}${h[15]}`; }
function rnd(n){ const b=crypto.getRandomValues(new Uint8Array(n)); return btoa(String.fromCharCode(...b)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }
function b64e(s){ return btoa(unescape(encodeURIComponent(s))); }
function parseKey(s,enc){ s=(s||'').trim(); if(!s) return new Uint8Array(0);
  if(enc==='hex'||/^[0-9a-fA-F]+$/.test(s)&&s.length%2===0&&enc!=='b64'){ const a=new Uint8Array(s.length/2); for(let i=0;i<a.length;i++)a[i]=parseInt(s.substr(i*2,2),16); return a; }
  const bin=atob(s.replace(/-/g,'+').replace(/_/g,'/')); const a=new Uint8Array(bin.length); for(let i=0;i<bin.length;i++)a[i]=bin.charCodeAt(i); return a; }

/* ========== VPN STUDIO ========== */
function studioProfile(){
  return { protocol:$('stProto').value, address:$('stAddr').value||'my.server.net',
    port:+$('stPort').value||443, network:$('stNet').value, security:$('stSec').value,
    sni:$('stSni').value||$('stAddr').value, path:$('stPath').value||'/', tag:$('stTag').value||'DLU',
    uuid:uuid4(), password:rnd(16) };
}
let STUDIO=null;
function buildLink(p){
  if(p.protocol==='vmess'){ const j={v:'2',ps:p.tag,add:p.address,port:String(p.port),id:p.uuid,aid:'0',scy:'auto',net:p.network,type:'none',host:p.sni,path:p.path,tls:p.security==='none'?'':'tls',sni:p.sni};
    return 'vmess://'+b64e(JSON.stringify(j)); }
  if(p.protocol==='vless'||p.protocol==='trojan'){ const id=p.protocol==='vless'?p.uuid:p.password;
    let q='type='+p.network+'&security='+p.security; if(p.sni)q+='&sni='+encodeURIComponent(p.sni);
    if(p.network==='ws'){ q+='&host='+encodeURIComponent(p.sni)+'&path='+encodeURIComponent(p.path); }
    if(p.network==='grpc') q+='&serviceName='+encodeURIComponent(p.path.replace(/^\//,''));
    if(p.security==='reality') q+='&flow=xtls-rprx-vision&pbk=REPLACE_PUBLIC_KEY&sid=REPLACE_SHORTID';
    return p.protocol+'://'+encodeURIComponent(id)+'@'+p.address+':'+p.port+'?'+q+'#'+encodeURIComponent(p.tag); }
  if(p.protocol==='shadowsocks'){ return 'ss://'+b64e('chacha20-ietf-poly1305:'+p.password)+'@'+p.address+':'+p.port+'#'+encodeURIComponent(p.tag); }
  return '';
}
function buildClientJSON(p){
  const ob={tag:p.tag,protocol:p.protocol,settings:{},streamSettings:{network:p.network,security:p.security==='none'?'none':p.security}};
  if(p.protocol==='vmess'||p.protocol==='vless') ob.settings.vnext=[{address:p.address,port:p.port,users:[p.protocol==='vmess'?{id:p.uuid,alterId:0,security:'auto'}:{id:p.uuid,encryption:'none',flow:p.security==='reality'?'xtls-rprx-vision':''}]}];
  else if(p.protocol==='trojan') ob.settings.servers=[{address:p.address,port:p.port,password:p.password}];
  else if(p.protocol==='shadowsocks') ob.settings.servers=[{address:p.address,port:p.port,password:p.password,method:'chacha20-ietf-poly1305'}];
  if(p.security==='tls') ob.streamSettings.tlsSettings={serverName:p.sni,allowInsecure:false};
  if(p.security==='reality') ob.streamSettings.realitySettings={serverName:p.sni,publicKey:'REPLACE_PUBLIC_KEY',shortId:'REPLACE_SHORTID',fingerprint:'chrome'};
  if(p.network==='ws') ob.streamSettings.wsSettings={path:p.path,headers:{Host:p.sni}};
  if(p.network==='grpc') ob.streamSettings.grpcSettings={serviceName:p.path.replace(/^\//,'')};
  return JSON.stringify({log:{loglevel:'warning'},inbounds:[{tag:'socks',port:10808,listen:'127.0.0.1',protocol:'socks',settings:{udp:true}}],outbounds:[ob,{tag:'direct',protocol:'freedom'}]},null,2);
}
function buildYAML(p){
  let y='proxies:\n';
  if(p.protocol==='vless'||p.protocol==='vmess'){ y+=`  - name: "${p.tag}"\n    type: ${p.protocol}\n    server: ${p.address}\n    port: ${p.port}\n`;
    y+=p.protocol==='vmess'?`    uuid: ${p.uuid}\n    alterId: 0\n    cipher: auto\n`:`    uuid: ${p.uuid}\n`;
    y+=`    network: ${p.network}\n    tls: ${p.security!=='none'}\n    servername: ${p.sni}\n`;
    if(p.network==='ws') y+=`    ws-opts:\n      path: ${p.path}\n      headers:\n        Host: ${p.sni}\n`; }
  else if(p.protocol==='trojan'){ y+=`  - name: "${p.tag}"\n    type: trojan\n    server: ${p.address}\n    port: ${p.port}\n    password: ${p.password}\n    sni: ${p.sni}\n`; }
  else if(p.protocol==='shadowsocks'){ y+=`  - name: "${p.tag}"\n    type: ss\n    server: ${p.address}\n    port: ${p.port}\n    cipher: chacha20-ietf-poly1305\n    password: ${p.password}\n`; }
  else y+=`  # ${p.protocol} : voir le fichier généré (non Clash)\n`;
  return y;
}
function buildScript(p){ // for ssh/slowdns/udp/wireguard/openvpn reuse app.js gen()? build here
  if(p.protocol==='wireguard') return `[Interface]\nPrivateKey = ${rnd(32)}\nAddress = 10.66.66.2/32\nDNS = 1.1.1.1\n\n[Peer]\nPublicKey = REPLACE_SERVER_PUBKEY\nEndpoint = ${p.address}:${p.port===443?51820:p.port}\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n`;
  if(p.protocol==='openvpn') return `client\ndev tun\nproto udp\nremote ${p.address} ${p.port===443?1194:p.port}\nnobind\npersist-key\npersist-tun\nremote-cert-tls server\ncipher AES-256-GCM\nauth SHA256\nverb 3\n# <ca>/<cert>/<key> depuis votre PKI\n`;
  if(p.protocol==='ssh') return `#!/usr/bin/env bash\nset -euo pipefail\nssh -N -D 127.0.0.1:1080 -p ${p.port===443?22:p.port} user@${p.address}\n# socks5://127.0.0.1:1080\n`;
  if(p.protocol==='slowdns') return `#!/usr/bin/env bash\nset -euo pipefail\ndnstt-client -udp 8.8.8.8:53 -pubkey REPLACE_PUBKEY ns.${p.address} 127.0.0.1:2222\n`;
  if(p.protocol==='udp') return JSON.stringify({listen:':36712',auth:{mode:'passwords',passwords:[p.password]},ignore_list:[]},null,2);
  return '';
}
function studioRender(){
  const p=STUDIO; const link=buildLink(p);
  const linkEl=$('stLink'), qr=$('stQR'), out=$('stOut');
  const uriProtos=['vless','vmess','trojan','shadowsocks'];
  if(uriProtos.includes(p.protocol)){
    linkEl.innerHTML=`<b>Lien de partage :</b><div class="code" style="margin-top:8px">${esc(link)}</div>`;
    try{ if(window.QR&&link){ QR.toCanvas(qr,link,'M',4,4); qr.style.display='block'; } }catch(e){ qr.style.display='none'; }
  } else { linkEl.innerHTML=`<p class="note">${esc(p.protocol)} : pas de lien URI — fichier de config généré ci-dessous.</p>`; qr.style.display='none'; }
  const fmt=$('stFmt').value;
  if(uriProtos.includes(p.protocol)){
    out.textContent = fmt==='json'?buildClientJSON(p) : fmt==='yaml'?buildYAML(p) : link;
  } else { out.textContent = buildScript(p); }
}
$('stGen').onclick=()=>{ STUDIO=studioProfile(); studioRender(); if(typeof logReport==='function') logReport({kind:'studio',file:STUDIO.protocol,verdict:'config générée'}); };
$('stFmt').onchange=()=>{ if(STUDIO) studioRender(); };
$('stCopyLink').onclick=()=>{ if(STUDIO) navigator.clipboard.writeText(buildLink(STUDIO)||$('stOut').textContent); };
$('stDownload').onclick=()=>{ if(!STUDIO) return; const c=$('stOut').textContent; const ext=$('stFmt').value==='json'?'json':$('stFmt').value==='yaml'?'yaml':'txt';
  const a=document.createElement('a'); a.href=URL.createObjectURL(new Blob([c])); a.download=STUDIO.protocol+'_config.'+ext; a.click(); };
$('stValidate').onclick=()=>{ if(!STUDIO){ $('stValid').innerHTML='<p class="note">Générez d\'abord une config.</p>'; return; }
  const p=STUDIO; const f=[];
  if(!/^[a-z0-9.-]+$/i.test(p.address)) f.push(['high','Adresse invalide']);
  if(p.port<1||p.port>65535) f.push(['high','Port hors plage']);
  if((p.protocol==='vless'||p.protocol==='vmess')&&!/^[0-9a-f-]{36}$/i.test(p.uuid)) f.push(['high','UUID invalide']);
  if(p.security==='none'&&['vless','vmess','trojan'].includes(p.protocol)) f.push(['medium','Transport sans TLS']);
  if(p.security==='reality') f.push(['info','REALITY : remplacez publicKey/shortId par ceux de votre serveur']);
  let o='<b>Validation (syntaxe/cohérence) :</b> ';
  o+= f.length? '<br>'+f.map(x=>`<span class="tag sev-${x[0]}">${x[0]}</span> ${esc(x[1])}`).join('<br>') : '<span class="tag sev-low">OK</span> structure cohérente.';
  o+='<p class="note">⚠ « Valide » = structure correcte, pas « connexion confirmée ». Testez avec un client réel.</p>';
  $('stValid').innerHTML=o;
};

/* ========== BINARY ANALYZER ========== */
document.querySelectorAll('[data-btab]').forEach(t=>t.onclick=()=>{
  const g=t.closest('.panel');
  g.querySelectorAll('[data-btab]').forEach(x=>x.classList.toggle('active',x===t));
  g.querySelectorAll('.btabpanel').forEach(p=>p.classList.toggle('active',p.dataset.btabPanel===t.dataset.btab));
});
function hexdump(bytes,max){ max=max||4096; let o=''; const n=Math.min(bytes.length,max);
  for(let off=0;off<n;off+=16){ o+=off.toString(16).padStart(8,'0')+'  '; let asc='';
    for(let i=0;i<16;i++){ if(off+i<n){ const b=bytes[off+i]; o+=b.toString(16).padStart(2,'0')+' '; asc+=(b>=32&&b<127)?String.fromCharCode(b):'.'; } else { o+='   '; asc+=' '; } if(i===7)o+=' '; }
    o+=' |'+asc+'|\n'; }
  if(bytes.length>max) o+='... (tronqué)\n'; return o; }
function extractStrings(bytes,min){ min=min||4; const out=[]; let cur='';
  for(const b of bytes){ if(b>=32&&b<127) cur+=String.fromCharCode(b); else { if(cur.length>=min) out.push(cur); cur=''; if(out.length>500)break; } }
  if(cur.length>=min) out.push(cur); return out; }
async function analyzeBinary(file){
  const buf=await file.arrayBuffer(), bytes=new Uint8Array(buf);
  $('binHex').textContent=hexdump(bytes,4096);
  $('binStr').textContent=extractStrings(bytes,4).slice(0,400).join('\n')||'(aucune chaîne ≥4)';
  const H=entropy(bytes.slice(0,1<<20));
  let magic=''; const sig=[[[0x89,0x50,0x4E,0x47],'PNG'],[[0x50,0x4B,0x03,0x04],'ZIP'],[[0x25,0x50,0x44,0x46],'PDF'],[[0x7F,0x45,0x4C,0x46],'ELF'],[[0x1F,0x8B],'GZIP'],[[0xFF,0xD8,0xFF],'JPEG']];
  for(const [m,l] of sig){ if(m.every((v,i)=>bytes[i]===v)){ magic=l; break; } }
  $('binMeta').innerHTML=kv('Fichier',file.name)+kv('Taille',bytes.length+' octets')+kv('Magic',magic||'inconnu')
    +kv('Entropie',H.toFixed(3)+' bits/octet')+kv('Chaînes ≥4',extractStrings(bytes,4).length)
    +'<p class="note">Entropie haute ≠ chiffrement.</p>';
}
wireDrop('binDrop','binFile',analyzeBinary);
$('binBrowse').onclick=()=>$('binFile').click();

/* ========== CRYPTO INTELLIGENCE ========== */
$('cryBtn').onclick=async()=>{
  const op=$('cryOp').value, enc=$('cryEnc').value, el=$('cryResult');
  const raw=$('cryIn').value.trim(); if(!raw){ el.innerHTML='<p class="red">Entrée vide.</p>'; return; }
  let data; try{ data=parseKey(raw,enc); }catch(e){ el.innerHTML='<p class="red">Entrée invalide.</p>'; return; }
  if(op==='detect'){
    const txt=new TextDecoder('utf-8',{fatal:false}).decode(data);
    const H=entropy(data);
    let o=kv('Octets décodés',data.length)+kv('Entropie',H.toFixed(3));
    const printable=[...data.slice(0,200)].filter(b=>b>=32&&b<127).length/Math.min(200,data.length||1);
    o+=kv('Aspect',printable>0.85?'texte lisible':H>7.3?'haute entropie (compressé/chiffré)':'binaire');
    if(printable>0.85) o+=`<div class="code">${esc(txt.slice(0,2000))}</div>`;
    el.innerHTML=o; return;
  }
  // AES with user key
  try{
    const key=parseKey($('cryKey').value,enc), iv=parseKey($('cryIv').value,enc);
    if(key.length!==16&&key.length!==32){ el.innerHTML='<p class="red">Clé AES = 16 ou 32 octets requis.</p>'; return; }
    const algo=op==='aesgcm'?{name:'AES-GCM',iv}:{name:'AES-CBC',iv};
    const ck=await crypto.subtle.importKey('raw',key,{name:algo.name},false,['decrypt']);
    const pt=await crypto.subtle.decrypt(algo,ck,data);
    const txt=new TextDecoder('utf-8',{fatal:false}).decode(pt);
    el.innerHTML=`<b class="red">Déchiffré (${pt.byteLength} o) :</b><div class="code">${esc(txt.slice(0,4000))}</div><p class="note">Opère uniquement sur VOS données, avec VOTRE clé.</p>`;
  }catch(e){ el.innerHTML='<p class="red">Échec du déchiffrement : clé/IV/tag incorrects, ou données non conformes. DecryptLab ne devine pas de clé.</p>'; }
};

/* ========== COMPARISON ========== */
$('cmpBtn').onclick=()=>{
  const A=parseVPN($('cmpA').value), B=parseVPN($('cmpB').value);
  const pa=A.profiles[0]||{}, pb=B.profiles[0]||{};
  if(!A.profiles.length||!B.profiles.length){ $('cmpResult').innerHTML='<p class="red">Deux configs valides requises.</p>'; return; }
  const fields=['protocol','address','port','network','security','uuid','password','method','sni','tag'];
  let o='<b>Différences :</b><div class="result">'; let diffs=0;
  for(const f of fields){ const a=pa[f]||'—', b=pb[f]||'—';
    if(String(a)!==String(b)){ diffs++; o+=`<div class="kv"><span class="red">${f}</span><b>A: ${esc(String(a))} &nbsp;|&nbsp; B: ${esc(String(b))}</b></div>`; } }
  o+= diffs?'':'<p class="note">Identiques sur les champs comparés.</p>'; o+='</div>';
  $('cmpResult').innerHTML=o;
};
