// qrcrypto.js
// Minimal AES-GCM + PBKDF2 helper with Base64URL packing.
// Payload format: "QRX1." + base64url(JSON)
// JSON fields: v, alg, kdf, salt, iv, aad, ct
// - v: version string ("1")
// - alg: "AES-GCM-256"
// - kdf: { name: "PBKDF2", hash:"SHA-256", iters:250000, salt:<b64url> }
// - iv: 12-byte iv (b64url)
// - aad: base64url of UTF-8(aadString)  (optional)
// - ct: ciphertext (includes GCM tag) (b64url)
// AAD binds app_id (or any domain string) into auth tag.

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function toB64Url(bytes){
  const bin = Array.from(bytes, b => String.fromCharCode(b)).join('');
  const b64 = btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/,'');
  return b64;
}
function fromB64Url(b64url){
  const b64 = b64url.replace(/-/g,'+').replace(/_/g,'/');
  const pad = '='.repeat((4 - (b64.length % 4)) % 4);
  const bin = atob(b64 + pad);
  const bytes = new Uint8Array(bin.length);
  for(let i=0;i<bin.length;i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

async function deriveKeyFromPassphrase(passphrase, salt, iters=250000){
  const baseKey = await crypto.subtle.importKey(
    'raw', textEncoder.encode(passphrase),
    {name:'PBKDF2'}, false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    {name:'PBKDF2', salt, iterations: iters, hash:'SHA-256'},
    baseKey,
    {name:'AES-GCM', length:256},
    false,
    ['encrypt','decrypt']
  );
}

// Encrypts plaintext with passphrase and optional aadString (e.g., app_id)
export async function encryptToToken(plaintext, passphrase, aadString=''){
  const v = '1';
  const alg = 'AES-GCM-256';
  const kdf = { name:'PBKDF2', hash:'SHA-256', iters:250000 };
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKeyFromPassphrase(passphrase, salt, kdf.iters);
  const aad = aadString ? textEncoder.encode(aadString) : new Uint8Array();
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    {name:'AES-GCM', iv, additionalData: aad.byteLength ? aad : undefined},
    key,
    textEncoder.encode(plaintext)
  ));
  const obj = {
    v,
    alg,
    kdf:{...kdf, salt: toB64Url(salt)},
    iv: toB64Url(iv),
    aad: aadString ? toB64Url(aad) : '',
    ct: toB64Url(ct),
  };
  const packed = 'QRX1.' + toB64Url(textEncoder.encode(JSON.stringify(obj)));
  return packed;
}

// Decrypts a token back to plaintext, validating version and (optionally) expected aadString
export async function decryptFromToken(token, passphrase, expectedAadString=''){
  if(!token || !token.startsWith('QRX1.')) throw new Error('Token format is invalid');
  const b64 = token.slice(5);
  let obj;
  try{
    obj = JSON.parse(textDecoder.decode(fromB64Url(b64)));
  }catch(e){ throw new Error('Token payload is not valid JSON'); }
  if(obj.v !== '1' || obj.alg !== 'AES-GCM-256' || !obj.kdf) throw new Error('Unsupported token');
  const salt = fromB64Url(obj.kdf.salt);
  const iv = fromB64Url(obj.iv);
  const aadBytes = obj.aad ? fromB64Url(obj.aad) : new Uint8Array();
  const ct = fromB64Url(obj.ct);
  // AAD check (bind to app_id/domain to ensure only your app intends to read it)
  if(expectedAadString){
    const expected = textEncoder.encode(expectedAadString);
    if(aadBytes.length !== expected.length || !aadBytes.every((b,i)=>b===expected[i])){
      throw new Error('App binding mismatch (AAD)');
    }
  }
  const key = await deriveKeyFromPassphrase(passphrase, salt, obj.kdf.iters);
  const ptBytes = new Uint8Array(await crypto.subtle.decrypt(
    {name:'AES-GCM', iv, additionalData: aadBytes.length ? aadBytes : undefined},
    key,
    ct
  ));
  return textDecoder.decode(ptBytes);
}
