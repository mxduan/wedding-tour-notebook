'use strict';
const status=document.querySelector('#status'),button=document.querySelector('#submit'),field=document.querySelector('#password');
const bytes=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0)),enc=new TextEncoder();
const digest=async b=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',b)),n=>n.toString(16).padStart(2,'0')).join('');
async function json(name){const r=await fetch(name,{cache:'no-store'});if(!r.ok)throw Error('Download unavailable');return r.json();}
async function load(){
 const [m,b]=await Promise.all([json('payload.json'),json('reader-key.json')]);
 if(m.version!==2||m.protocol!=='wedding-notebook-envelope-v2'||m.cipher!=='AES-256-GCM'||b.version!==2||b.algorithm!=='RSA-OAEP-SHA256'||b.modulusLength!==3072||m.keyId!==b.keyId||!/^[a-f0-9]{64}$/.test(m.keyId)||!/^[-\w.]{1,80}$/.test(m.revision)||!Number.isSafeInteger(m.bytes)||m.bytes<16||m.bytes>250*1024*1024||!Array.isArray(m.chunks)||m.chunks.length<1||m.chunks.length>64||m.chunks.some((n,i)=>n!==`notebook-${i}.bin`))throw Error('Unsupported or damaged notebook metadata.');
 if(await digest(bytes(b.publicKey))!==b.keyId||bytes(m.iv).length!==12||bytes(m.wrappedContentKey).length!==384)throw Error('Damaged notebook metadata.');
 const w=b.privateKeyEnvelope;
 if(w?.kdf!=='PBKDF2-SHA256'||w.iterations!==600000||w.cipher!=='AES-256-GCM'||bytes(w.salt).length!==32||bytes(w.iv).length!==12||bytes(w.ciphertext).length<1500||bytes(w.ciphertext).length>4000)throw Error('Unsupported protected reader key.');
 const cipher=new Uint8Array(m.bytes);let pos=0;
 for(const name of m.chunks){const r=await fetch(name,{cache:'no-store'});if(!r.ok)throw Error('Download unavailable');const a=new Uint8Array(await r.arrayBuffer());if(pos+a.length>m.bytes)throw Error('Damaged notebook download.');cipher.set(a,pos);pos+=a.length;status.textContent=`Loading photos and notes… ${Math.round(pos/m.bytes*100)}%`;}
 if(pos!==m.bytes||await digest(cipher)!==m.sha256)throw Error('Notebook download is incomplete or damaged. Reload and try again.');
 return {m,b,cipher};
}
document.querySelector('#unlock').addEventListener('submit',async e=>{
 e.preventDefault();button.disabled=true;status.textContent='Opening notebook…';
 let password=field.value;field.value='';
 try{
  if(!crypto.subtle||!window.DecompressionStream)throw Error('Use a current browser with HTTPS.');
  const material=await crypto.subtle.importKey('raw',enc.encode(password),'PBKDF2',false,['deriveKey']);password='';
  const {m,b,cipher}=await load(),w=b.privateKeyEnvelope;
  status.textContent='Checking password…';
  const wrapping=await crypto.subtle.deriveKey({name:'PBKDF2',salt:bytes(w.salt),iterations:w.iterations,hash:'SHA-256'},material,{name:'AES-GCM',length:256},false,['decrypt']);
  let pkcs8;try{pkcs8=await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes(w.iv),additionalData:enc.encode('wedding-notebook-reader-key-v2|'+b.keyId)},wrapping,bytes(w.ciphertext));}catch{throw Error('That password did not unlock the notebook. Try again.');}
  const reader=await crypto.subtle.importKey('pkcs8',pkcs8,{name:'RSA-OAEP',hash:'SHA-256'},false,['decrypt']);new Uint8Array(pkcs8).fill(0);
  let raw;try{raw=await crypto.subtle.decrypt({name:'RSA-OAEP'},reader,bytes(m.wrappedContentKey));}catch{throw Error('The protected notebook key is damaged.');}
  if(raw.byteLength!==32)throw Error('Invalid content key.');
  const aes=await crypto.subtle.importKey('raw',raw,'AES-GCM',false,['decrypt']);new Uint8Array(raw).fill(0);
  let compressed;try{compressed=await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes(m.iv),additionalData:enc.encode(`wedding-notebook-envelope-v2|${m.keyId}|${m.revision}`)},aes,cipher);}catch{throw Error('Notebook authentication failed. Reload and try again.');}
  const html=await new Response(new Blob([compressed]).stream().pipeThrough(new DecompressionStream('gzip'))).text();
  document.open();document.write(html);document.close();
 }catch(err){password='';field.value='';status.textContent=err.message;button.disabled=false;}
});
