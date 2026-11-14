'use strict';
/* Compact, dependency-free QR Code generator (byte mode).
   Faithful reimplementation of the well-known Arase algorithm (MIT/public-domain
   lineage). Supports EC levels L/M/Q/H, auto version, best-mask selection,
   and multi-block interleaving. Exposes window.QR.make(text, ecLevel) -> {size, modules}. */
(function(global){
  // ---- Galois field (GF256) ----
  const EXP=new Array(256), LOG=new Array(256);
  (function(){ let x=1; for(let i=0;i<255;i++){ EXP[i]=x; LOG[x]=i; x<<=1; if(x&0x100) x^=0x11d; } for(let i=255;i<256;i++) EXP[i]=EXP[i-255]; })();
  function gmul(a,b){ if(a===0||b===0) return 0; return EXP[(LOG[a]+LOG[b])%255]; }
  function rsGenPoly(n){ let poly=[1]; for(let i=0;i<n;i++){ const np=new Array(poly.length+1).fill(0);
    for(let j=0;j<poly.length;j++){ np[j]^=poly[j]; np[j+1]^=gmul(poly[j],EXP[i]); } poly=np; } return poly; }
  function rsEncode(data,n){ const gen=rsGenPoly(n); const res=new Array(n).fill(0);
    for(let i=0;i<data.length;i++){ const factor=data[i]^res[0]; res.shift(); res.push(0);
      if(factor!==0) for(let j=0;j<gen.length;j++) res[j]^=gmul(gen[j],factor); } return res; }

  // ---- capacity & EC tables (byte mode data codewords per version/level) ----
  // [ecCodewordsPerBlock, numBlocksGroup1, dataCwGroup1, numBlocksGroup2, dataCwGroup2]
  const EC={L:0,M:1,Q:2,H:3};
  const RSBLOCK=[
    // v1
    [[7,1,19,0,0],[10,1,16,0,0],[13,1,13,0,0],[17,1,9,0,0]],
    [[10,1,34,0,0],[16,1,28,0,0],[22,1,22,0,0],[28,1,16,0,0]],
    [[15,1,55,0,0],[26,1,44,0,0],[18,2,17,0,0],[22,2,13,0,0]],
    [[20,1,80,0,0],[18,2,32,0,0],[26,2,24,0,0],[16,4,9,0,0]],
    [[26,1,108,0,0],[24,2,43,0,0],[18,2,15,2,16],[22,2,11,2,12]],
    [[18,2,68,0,0],[16,4,27,0,0],[24,4,19,0,0],[28,4,15,0,0]],
    [[20,2,78,0,0],[18,4,31,0,0],[18,2,14,4,15],[26,4,13,1,14]],
    [[24,2,97,0,0],[22,2,38,2,39],[22,4,18,2,19],[26,4,14,2,15]],
    [[30,2,116,0,0],[22,3,36,2,37],[20,4,16,4,17],[24,4,12,4,13]],
    [[18,2,68,2,69],[26,4,43,1,44],[24,6,19,2,20],[28,6,15,2,16]]
  ];
  const ALIGN=[[],[],[6,18],[6,22],[6,26],[6,30],[6,34],[6,22,38],[6,24,42],[6,26,46],[6,28,50]];

  function versionCapacity(v,ecl){ const b=RSBLOCK[v-1][ecl]; return b[1]*b[2]+b[3]*b[4]; }
  function pickVersion(len,ecl){ for(let v=1;v<=10;v++){ // header: 4(mode)+8or16(count) bits
      const countBits=(v<10)?8:16; const cap=versionCapacity(v,ecl); const need=Math.ceil((4+countBits+len*8)/8);
      if(need<=cap) return v; } return -1; }

  // ---- bit buffer ----
  function BitBuf(){ this.bits=[]; }
  BitBuf.prototype.put=function(num,len){ for(let i=len-1;i>=0;i--) this.bits.push((num>>i)&1); };

  function makeData(text, ecl){
    const bytes=[]; for(let i=0;i<text.length;i++){ const c=text.charCodeAt(i);
      if(c<0x80) bytes.push(c);
      else if(c<0x800){ bytes.push(0xC0|(c>>6)); bytes.push(0x80|(c&0x3F)); }
      else { bytes.push(0xE0|(c>>12)); bytes.push(0x80|((c>>6)&0x3F)); bytes.push(0x80|(c&0x3F)); } }
    const v=pickVersion(bytes.length,ecl);
    if(v<0) throw new Error('données trop longues pour un QR v1-10');
    const bb=new BitBuf();
    bb.put(4,4); // byte mode
    bb.put(bytes.length,(v<10)?8:16);
    for(const b of bytes) bb.put(b,8);
    const cap=versionCapacity(v,ecl)*8;
    // terminator
    for(let i=0;i<4 && bb.bits.length<cap;i++) bb.bits.push(0);
    while(bb.bits.length%8!==0) bb.bits.push(0);
    const dcw=[]; for(let i=0;i<bb.bits.length;i+=8){ let n=0; for(let j=0;j<8;j++) n=(n<<1)|bb.bits[i+j]; dcw.push(n); }
    const capCw=versionCapacity(v,ecl); let pad=[0xEC,0x11],pi=0;
    while(dcw.length<capCw){ dcw.push(pad[pi%2]); pi++; }
    // split into blocks
    const info=RSBLOCK[v-1][ecl]; const ecLen=info[0];
    const blocks=[]; let idx=0;
    for(let g=0;g<info[1];g++){ blocks.push(dcw.slice(idx,idx+info[2])); idx+=info[2]; }
    for(let g=0;g<info[3];g++){ blocks.push(dcw.slice(idx,idx+info[4])); idx+=info[4]; }
    const ecBlocks=blocks.map(b=>rsEncode(b,ecLen));
    // interleave data
    const result=[]; const maxd=Math.max(...blocks.map(b=>b.length));
    for(let i=0;i<maxd;i++) for(const b of blocks) if(i<b.length) result.push(b[i]);
    const maxe=ecLen; for(let i=0;i<maxe;i++) for(const b of ecBlocks) if(i<b.length) result.push(b[i]);
    return {version:v, data:result};
  }

  // ---- matrix ----
  function makeMatrix(version){ const size=version*4+17; const m=[]; for(let i=0;i<size;i++) m.push(new Array(size).fill(null)); return m; }
  function placeFinder(m,r,c){ for(let i=-1;i<=7;i++) for(let j=-1;j<=7;j++){ const rr=r+i,cc=c+j;
    if(rr<0||cc<0||rr>=m.length||cc>=m.length) continue;
    const v=(i>=0&&i<=6&&(j===0||j===6))||(j>=0&&j<=6&&(i===0||i===6))||(i>=2&&i<=4&&j>=2&&j<=4);
    m[rr][cc]=v?1:0; } }
  function placeAlign(m,v){ const pos=ALIGN[v]; for(const r of pos) for(const c of pos){
    if(m[r][c]!==null) continue; for(let i=-2;i<=2;i++) for(let j=-2;j<=2;j++){
      const vv=Math.max(Math.abs(i),Math.abs(j)); m[r+i][c+j]=(vv!==1)?1:0; } } }
  function placeTiming(m){ for(let i=8;i<m.length-8;i++){ if(m[6][i]===null) m[6][i]=(i%2===0)?1:0; if(m[i][6]===null) m[i][6]=(i%2===0)?1:0; } }

  const FORMAT=[ // precomputed 15-bit format strings, indexed by (ecBits<<3 | mask)
    // ecBits: L=1,M=0,Q=3,H=2 (QR spec ordering)
  ];
  function bchFormat(data){ let d=data<<10; const g=0x537;
    for(let i=14;i>=10;i--) if((d>>i)&1) d^=g<<(i-10); return ((data<<10)|d)^0x5412; }
  function placeFormat(m,eclBits,mask){ const size=m.length; const bits=bchFormat((eclBits<<3)|mask);
    for(let i=0;i<15;i++){ const b=(bits>>i)&1;
      // around top-left
      if(i<6) m[i][8]=b; else if(i<8) m[i+1][8]=b; else if(i===8) m[8][7]=b; else m[8][14-i]=b;
      // around top-right / bottom-left
      if(i<8) m[8][size-1-i]=b; else m[size-15+i][8]=b; }
    m[size-8][8]=1; }

  function reserveFormat(m){ const size=m.length; for(let i=0;i<9;i++){ if(m[8][i]===null)m[8][i]=0; if(m[i][8]===null)m[i][8]=0; }
    for(let i=0;i<8;i++){ if(m[8][size-1-i]===null)m[8][size-1-i]=0; if(m[size-1-i][8]===null)m[size-1-i][8]=0; } }

  function maskFn(mask,r,c){ switch(mask){
    case 0:return (r+c)%2===0; case 1:return r%2===0; case 2:return c%3===0; case 3:return (r+c)%3===0;
    case 4:return (Math.floor(r/2)+Math.floor(c/3))%2===0; case 5:return (r*c)%2+(r*c)%3===0;
    case 6:return ((r*c)%2+(r*c)%3)%2===0; case 7:return ((r+c)%2+(r*c)%3)%2===0; } return false; }

  function mapData(m,data,mask){ const size=m.length; let bitIdx=0; let dir=-1;
    for(let col=size-1;col>0;col-=2){ if(col===6) col--;
      for(let i=0;i<size;i++){ const row=(dir===-1)?size-1-i:i;
        for(let k=0;k<2;k++){ const cc=col-k;
          if(m[row][cc]!==null) continue;
          let bit=0; if(bitIdx<data.length*8){ const byte=data[bitIdx>>3]; bit=(byte>>(7-(bitIdx&7)))&1; bitIdx++; }
          if(maskFn(mask,row,cc)) bit^=1; m[row][cc]=bit; } }
      dir=-dir; } }

  function penalty(m){ const size=m.length; let p=0;
    for(let r=0;r<size;r++){ let run=1; for(let c=1;c<size;c++){ if(m[r][c]===m[r][c-1]){run++; if(run===5)p+=3; else if(run>5)p++;} else run=1; } }
    for(let c=0;c<size;c++){ let run=1; for(let r=1;r<size;r++){ if(m[r][c]===m[r-1][c]){run++; if(run===5)p+=3; else if(run>5)p++;} else run=1; } }
    for(let r=0;r<size-1;r++) for(let c=0;c<size-1;c++){ const v=m[r][c]; if(v===m[r][c+1]&&v===m[r+1][c]&&v===m[r+1][c+1]) p+=3; }
    let dark=0; for(let r=0;r<size;r++) for(let c=0;c<size;c++) dark+=m[r][c];
    const pct=dark*100/(size*size); p+=Math.floor(Math.abs(pct-50)/5)*10; return p; }

  function make(text, ecLevel){
    const ecl=EC[ecLevel||'M'];
    const {version,data}=makeData(text,ecl);
    const eclBitsMap=[1,0,3,2]; // L,M,Q,H -> spec bits
    let best=null,bestPen=Infinity;
    for(let mask=0;mask<8;mask++){
      const m=makeMatrix(version);
      placeFinder(m,0,0); placeFinder(m,0,m.length-7); placeFinder(m,m.length-7,0);
      placeAlign(m,version); placeTiming(m);
      m[m.length-8][8]=1; reserveFormat(m);
      mapData(m,data,mask);
      placeFormat(m,eclBitsMap[ecl],mask);
      const pen=penalty(m);
      if(pen<bestPen){ bestPen=pen; best=m; }
    }
    return {size:best.length, modules:best, version};
  }

  function toCanvas(canvas,text,ecLevel,scale,margin){
    const q=make(text,ecLevel); scale=scale||4; margin=(margin==null)?4:margin;
    const n=q.size, dim=(n+margin*2)*scale; canvas.width=dim; canvas.height=dim;
    const ctx=canvas.getContext('2d'); ctx.fillStyle='#fff'; ctx.fillRect(0,0,dim,dim);
    ctx.fillStyle='#000';
    for(let r=0;r<n;r++) for(let c=0;c<n;c++) if(q.modules[r][c]) ctx.fillRect((c+margin)*scale,(r+margin)*scale,scale,scale);
    return q;
  }

  global.QR={make,toCanvas,rsGenPoly,bchFormat};
})(typeof window!=='undefined'?window:globalThis);
