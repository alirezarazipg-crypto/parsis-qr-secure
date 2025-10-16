import express from 'express';
import QRCode from 'qrcode';
import crypto from 'crypto';
import dotenv from 'dotenv';
dotenv.config();

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(express.static('public'));

const te = new TextEncoder();
const td = new TextDecoder();

function b64url(buf){
  return Buffer.from(buf).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function fromB64url(s){
  s = s.replace(/-/g,'+').replace(/_/g,'/');
  const pad = '='.repeat((4 - (s.length % 4)) % 4);
  return Buffer.from(s + pad, 'base64');
}

const APP_ID = process.env.APP_ID || 'parsisgold.com/app';

let AES_KEY;
if(process.env.AES_KEY_HEX){
  AES_KEY = Buffer.from(process.env.AES_KEY_HEX, 'hex');
}else if(process.env.AES_KEY_B64){
  AES_KEY = Buffer.from(process.env.AES_KEY_B64, 'base64');
}else{
  console.error('Missing AES_KEY_HEX or AES_KEY_B64 in .env');
  process.exit(1);
}
if(AES_KEY.length !== 32){
  console.error('AES key must be 32 bytes (256-bit)');
  process.exit(1);
}

let ED25519_PRIV, ED25519_PUB;
if(process.env.ED25519_PRIVATE_PEM && process.env.ED25519_PUBLIC_PEM){
  ED25519_PRIV = crypto.createPrivateKey(process.env.ED25519_PRIVATE_PEM);
  ED25519_PUB = crypto.createPublicKey(process.env.ED25519_PUBLIC_PEM);
}else{
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  ED25519_PRIV = privateKey;
  ED25519_PUB = publicKey;
  console.warn('Ephemeral Ed25519 keys generated (set PEMs in .env for production)');
}

function encrypt(plaintext){
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', AES_KEY, iv, { authTagLength: 16 });
  cipher.setAAD(te.encode(APP_ID));
  const ct = Buffer.concat([cipher.update(te.encode(plaintext)), cipher.final()]);
  const tag = cipher.getAuthTag();
  const cttag = Buffer.concat([ct, tag]);
  const obj = { v:1, alg:'AES-GCM-256', iv:b64url(iv), aad:b64url(te.encode(APP_ID)), ct:b64url(cttag) };
  const canonical = `${obj.v}|${obj.alg}|${obj.iv}|${obj.aad}|${obj.ct}`;
  const sig = crypto.sign(null, Buffer.from(canonical), ED25519_PRIV);
  obj.sig = b64url(sig);
  const token = 'QRX1.' + b64url(Buffer.from(JSON.stringify(obj)));
  return token;
}

function decrypt(token){
  if(!token.startsWith('QRX1.')) throw new Error('Bad token');
  const payload = JSON.parse(td.decode(fromB64url(token.slice(5))));
  if(payload.v !== 1 || payload.alg !== 'AES-GCM-256') throw new Error('Unsupported token');
  const aadBytes = te.encode(APP_ID);
  if(b64url(aadBytes) !== payload.aad) throw new Error('App binding mismatch');
  const canonical = `${payload.v}|${payload.alg}|${payload.iv}|${payload.aad}|${payload.ct}`;
  const ok = crypto.verify(null, Buffer.from(canonical), ED25519_PUB, fromB64url(payload.sig));
  if(!ok) throw new Error('Bad signature');

  const iv = fromB64url(payload.iv);
  const cttag = fromB64url(payload.ct);
  const ct = cttag.slice(0,-16);
  const tag = cttag.slice(-16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', AES_KEY, iv, { authTagLength: 16 });
  decipher.setAAD(aadBytes);
  decipher.setAuthTag(tag);
  const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
  return td.decode(pt);
}

app.post('/api/encode', async (req,res)=>{
  try{
    const { plaintext, ecc='M' } = req.body || {};
    if(!plaintext || typeof plaintext !== 'string') return res.status(400).json({ error:'plaintext required' });
    const token = encrypt(plaintext);
    const svg = await QRCode.toString(token, { type:'svg', errorCorrectionLevel:ecc, margin:0, width:200 });
    const sizedSvg = svg.replace('<svg', '<svg width="20mm" height="20mm"');
    res.json({ token, svg: sizedSvg });
  }catch(e){ res.status(500).json({ error:e.message }); }
});

app.post('/api/decode', (req,res)=>{
  try{
    const { token } = req.body || {};
    if(!token) return res.status(400).json({ error:'token required' });
    const plaintext = decrypt(token);
    res.json({ plaintext });
  }catch(e){ res.status(400).json({ error:e.message }); }
});

app.get('/', (req,res)=> res.sendFile(process.cwd() + '/public/index.html'));
const PORT = process.env.PORT || 3000;
app.listen(PORT, ()=> console.log(`Server on http://localhost:${PORT}`));
