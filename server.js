// Lumi - servidor
const express = require('express');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
// No Railway, monte um Volume e ele preenche RAILWAY_VOLUME_MOUNT_PATH sozinho
const DATA_DIR = process.env.RAILWAY_VOLUME_MOUNT_PATH || process.env.DATA_DIR || path.join(__dirname, 'data');
const FILES_DIR = path.join(DATA_DIR, 'files');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const JWT_SECRET = process.env.JWT_SECRET || 'troque-este-segredo-no-railway';
const QUOTA_BYTES = Number(process.env.QUOTA_MB || 5120) * 1024 * 1024; // cota padrão por pessoa
// Cotas especiais: QUOTA_OVERRIDES="email1@x.com:256, email2@y.com:50" (valores em GB)
const QUOTA_OVERRIDES = new Map(String(process.env.QUOTA_OVERRIDES || '').split(',')
  .map(p => p.trim().split(':')).filter(([e, g]) => e && Number(g) > 0)
  .map(([e, g]) => [e.trim().toLowerCase(), Number(g) * 1024 ** 3]));
const MAX_FILE_BYTES = Number(process.env.MAX_FILE_MB || 2048) * 1024 * 1024; // 2 GB por arquivo
const ALLOW_SIGNUP = process.env.ALLOW_SIGNUP !== 'false';

if (JWT_SECRET === 'troque-este-segredo-no-railway') {
  console.warn('[aviso] Defina a variável JWT_SECRET no Railway.');
}

fs.mkdirSync(FILES_DIR, { recursive: true });

// ---------- Banco de dados simples em JSON ----------
let db = { users: [], files: [] };
if (fs.existsSync(DB_FILE)) {
  try { db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch (e) { console.error('db.json inválido', e); }
}
let saveTimer = null;
function saveDb() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    const tmp = DB_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(db));
    fs.renameSync(tmp, DB_FILE);
  }, 100);
}
const id = () => crypto.randomBytes(12).toString('hex');
const usedBytes = (userId) => db.files.filter(f => f.userId === userId).reduce((s, f) => s + f.size, 0);

// ---------- App ----------
const app = express();
app.set('trust proxy', 1);
app.use(express.json());
app.use(cookieParser());
let BUCKET_HOSTS = '';
try { const h = new URL(process.env.BUCKET_ENDPOINT).host; BUCKET_HOSTS = `https://${h} https://*.${h}`; } catch {}
// Cabeçalhos de segurança
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  if (process.env.NODE_ENV === 'production') res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'", "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com", "font-src https://fonts.gstatic.com",
    `img-src 'self' blob: data: ${BUCKET_HOSTS}`, `media-src 'self' blob: ${BUCKET_HOSTS}`, `frame-src 'self' ${BUCKET_HOSTS}`,
    `connect-src 'self' ${BUCKET_HOSTS}`,
    "frame-ancestors 'self'", "base-uri 'none'", "form-action 'self'", "object-src 'none'",
  ].join('; '));
  next();
});
// Bloqueia pedidos de alteração vindos de outros sites
app.use('/api', (req, res, next) => {
  if (req.method === 'GET' || req.method === 'HEAD') return next();
  const origin = req.get('origin');
  let host = null; try { host = origin && new URL(origin).host; } catch {}
  if (origin && host !== req.get('host')) return res.status(403).json({ error: 'Origem não permitida.' });
  next();
});
app.use(express.static(path.join(__dirname, 'public')));

function setSession(res, user) {
  const token = jwt.sign({ uid: user.id, tv: user.tv || 0 }, JWT_SECRET, { expiresIn: '30d' });
  res.cookie('lumi', token, {
    httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production',
    maxAge: 30 * 24 * 3600 * 1000,
  });
}
function auth(req, res, next) {
  try {
    const { uid, tv } = jwt.verify(req.cookies.lumi || '', JWT_SECRET);
    const user = db.users.find(u => u.id === uid);
    // sessão antiga (depois de trocar senha ou "sair de todos") deixa de valer
    if (!user || (tv || 0) !== (user.tv || 0)) throw new Error();
    req.user = user;
    next();
  } catch {
    res.status(401).json({ error: 'Faça login para continuar.' });
  }
}

// Proteção simples contra tentativa de senha em massa
const attempts = new Map();
function tooMany(key, max = 20) {
  const now = Date.now();
  const a = attempts.get(key) || { n: 0, t: now };
  if (now - a.t > 15 * 60 * 1000) { a.n = 0; a.t = now; }
  a.n++; attempts.set(key, a);
  return a.n > (key.startsWith('reg:') ? 5 : key.startsWith('ip:') ? 60 : max);
}

function weakPassword(p) {
  if (p.length < 8) return 'A senha precisa ter pelo menos 8 caracteres.';
  if (!/[A-Za-z]/.test(p) || !/\d/.test(p)) return 'Use letras e números na senha.';
  if (p.length > 200) return 'Senha longa demais.';
  return null;
}

// ---------- Código por e-mail ----------
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const EMAIL_FROM = process.env.EMAIL_FROM || '';
const EMAIL_ON = !!(RESEND_API_KEY && EMAIL_FROM);
console.log(EMAIL_ON ? '[e-mail] Códigos por e-mail ATIVADOS' : '[e-mail] Códigos por e-mail desativados (defina RESEND_API_KEY e EMAIL_FROM)');

// contas criadas antes do sistema de código já contam como confirmadas
for (const u of db.users) { if (u.verified === undefined) u.verified = true; if (!u.devices) u.devices = []; }

const challenges = new Map(); // ticket -> { userId, purpose, codeHash, exp, tries, sentAt }
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
setInterval(() => { const now = Date.now(); for (const [k, c] of challenges) if (c.exp < now) challenges.delete(k); }, 60 * 1000);

const SUBJECTS = {
  verify: 'Confirme seu e-mail no Lumi',
  login: 'Código para entrar no Lumi',
  reset: 'Código para criar uma nova senha no Lumi',
};
const LINES = {
  verify: 'Use o código abaixo para confirmar seu e-mail e ativar sua conta.',
  login: 'Alguém está entrando na sua conta de um aparelho novo. Se foi você, use o código abaixo.',
  reset: 'Use o código abaixo para criar uma nova senha.',
};

async function sendCode(user, purpose, code) {
  const html = `<div style="font-family:Arial,sans-serif;max-width:440px;margin:0 auto;padding:28px;background:#0f1630;color:#f3f1ea;border-radius:16px">
  <div style="font-size:24px;font-weight:800;margin-bottom:18px">Lumi</div>
  <p style="font-size:16px;line-height:1.5;margin:0 0 20px">Oi, ${user.name.replace(/[<>&]/g, '')}. ${LINES[purpose]}</p>
  <div style="font-size:36px;letter-spacing:10px;font-weight:800;background:#1b2550;border-radius:12px;padding:18px;text-align:center;color:#ffb36b">${code}</div>
  <p style="font-size:13px;color:#a9b0d3;line-height:1.5;margin:20px 0 0">O código vale por 10 minutos. Se você não pediu isso, ignore este e-mail e considere trocar sua senha.</p>
</div>`;
  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: EMAIL_FROM, to: [user.email], subject: SUBJECTS[purpose], html, text: `${LINES[purpose]} Código: ${code}. Vale por 10 minutos.` }),
  });
  if (!r.ok) { console.error('[e-mail] falha ao enviar', r.status, await r.text().catch(() => '')); throw new Error('mail'); }
}

async function startChallenge(user, purpose) {
  const ticket = crypto.randomBytes(18).toString('hex');
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  challenges.set(ticket, { userId: user ? user.id : null, purpose, codeHash: sha(ticket + code), exp: Date.now() + 10 * 60 * 1000, tries: 0, sentAt: Date.now() });
  if (user) await sendCode(user, purpose, code);
  return ticket;
}
function checkChallenge(ticket, code, purpose) {
  const c = challenges.get(String(ticket || ''));
  if (!c || c.purpose !== purpose || c.exp < Date.now()) return { error: 'O código expirou. Peça um novo.' };
  if (++c.tries > 5) { challenges.delete(ticket); return { error: 'Muitas tentativas erradas. Peça um novo código.' }; }
  const ok = c.userId && crypto.timingSafeEqual(Buffer.from(c.codeHash), Buffer.from(sha(ticket + String(code || '').replace(/\D/g, ''))));
  if (!ok) return { error: `Código incorreto. Restam ${5 - c.tries} tentativa(s).` };
  challenges.delete(ticket);
  return { user: db.users.find(u => u.id === c.userId) };
}

// aparelho de confiança: depois de confirmar o código uma vez, ele entra direto
function trustDevice(req, res, user) {
  let dev = req.cookies.lumi_dev;
  if (!dev || !/^[a-f0-9]{32}$/.test(dev)) dev = crypto.randomBytes(16).toString('hex');
  user.devices = (user.devices || []).filter(d => d.h !== sha(dev));
  user.devices.unshift({ h: sha(dev), ua: String(req.get('user-agent') || '').slice(0, 160), at: Date.now() });
  user.devices = user.devices.slice(0, 15);
  res.cookie('lumi_dev', dev, { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 365 * 24 * 3600 * 1000 });
}
const knownDevice = (req, user) => !!req.cookies.lumi_dev && (user.devices || []).some(d => d.h === sha(req.cookies.lumi_dev));

async function finishLogin(req, res, user, purpose) {
  if (!EMAIL_ON || (purpose !== 'verify' && user.verified && knownDevice(req, user))) {
    if (!EMAIL_ON) user.verified = true;
    trustDevice(req, res, user); saveDb(); setSession(res, user);
    return res.json({ ok: true });
  }
  try {
    const ticket = await startChallenge(user, user.verified ? 'login' : 'verify');
    res.json({ needCode: true, ticket, email: user.email, purpose: user.verified ? 'login' : 'verify' });
  } catch {
    res.status(502).json({ error: 'Não conseguimos enviar o código agora. Tente de novo em instantes.' });
  }
}

app.get('/api/config', (req, res) => res.json({ email: EMAIL_ON, direct: !!process.env.BUCKET_NAME }));

app.post('/api/register', async (req, res) => {
  if (tooMany('reg:' + req.ip)) return res.status(429).json({ error: 'Muitas contas criadas daqui. Tente mais tarde.' });
  if (!ALLOW_SIGNUP) return res.status(403).json({ error: 'Cadastros estão fechados.' });
  const name = String(req.body.name || '').trim().slice(0, 60);
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  if (!name || !/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Preencha nome e um e-mail válido.' });
  const weak = weakPassword(password);
  if (weak) return res.status(400).json({ error: weak });
  const existing = db.users.find(u => u.email === email);
  if (existing && existing.verified) return res.status(409).json({ error: 'Esse e-mail já tem conta. Entre com ele.' });
  if (existing) db.users = db.users.filter(u => u !== existing); // cadastro anterior nunca confirmado
  const user = { id: id(), name, email, hash: await bcrypt.hash(password, 12), tv: 0, verified: false, devices: [], createdAt: Date.now() };
  db.users.push(user); saveDb();
  finishLogin(req, res, user, 'verify');
});

app.post('/api/login', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  if (tooMany(req.ip + email) || tooMany('ip:' + req.ip)) return res.status(429).json({ error: 'Muitas tentativas. Espere alguns minutos.' });
  const user = db.users.find(u => u.email === email);
  if (!user || !(await bcrypt.compare(String(req.body.password || ''), user.hash))) {
    return res.status(401).json({ error: 'E-mail ou senha incorretos.' });
  }
  finishLogin(req, res, user, 'login');
});

app.post('/api/code', (req, res) => {
  if (tooMany('code:' + req.ip, 30)) return res.status(429).json({ error: 'Muitas tentativas. Espere alguns minutos.' });
  const c = challenges.get(String(req.body.ticket || ''));
  if (!c || c.purpose === 'reset') return res.status(400).json({ error: 'O código expirou. Peça um novo.' });
  const r = checkChallenge(req.body.ticket, req.body.code, c.purpose);
  if (r.error || !r.user) return res.status(400).json({ error: r.error || 'Código inválido.' });
  r.user.verified = true;
  trustDevice(req, res, r.user); saveDb(); setSession(res, r.user);
  res.json({ ok: true });
});

app.post('/api/resend', async (req, res) => {
  const c = challenges.get(String(req.body.ticket || ''));
  if (!c) return res.status(400).json({ error: 'O código expirou. Volte e tente de novo.' });
  if (Date.now() - c.sentAt < 45 * 1000) return res.status(429).json({ error: 'Espere alguns segundos antes de pedir outro código.' });
  const user = db.users.find(u => u.id === c.userId);
  challenges.delete(req.body.ticket);
  try { const ticket = await startChallenge(user, c.purpose); res.json({ ticket }); }
  catch { res.status(502).json({ error: 'Não conseguimos enviar o código agora. Tente de novo em instantes.' }); }
});

// Esqueci minha senha
app.post('/api/forgot', async (req, res) => {
  if (!EMAIL_ON) return res.status(503).json({ error: 'A recuperação por e-mail ainda não foi ativada.' });
  if (tooMany('forgot:' + req.ip, 8)) return res.status(429).json({ error: 'Muitos pedidos. Espere alguns minutos.' });
  const email = String(req.body.email || '').trim().toLowerCase();
  const user = db.users.find(u => u.email === email);
  try {
    // mesma resposta exista ou não a conta, para ninguém descobrir quais e-mails estão cadastrados
    const ticket = await startChallenge(user || null, 'reset');
    res.json({ ticket });
  } catch { res.status(502).json({ error: 'Não conseguimos enviar o código agora. Tente de novo em instantes.' }); }
});

app.post('/api/reset', async (req, res) => {
  if (tooMany('code:' + req.ip, 30)) return res.status(429).json({ error: 'Muitas tentativas. Espere alguns minutos.' });
  const weak = weakPassword(String(req.body.password || ''));
  if (weak) return res.status(400).json({ error: weak });
  const r = checkChallenge(req.body.ticket, req.body.code, 'reset');
  if (r.error || !r.user) return res.status(400).json({ error: r.error || 'Código incorreto.' });
  r.user.hash = await bcrypt.hash(String(req.body.password), 12);
  r.user.tv = (r.user.tv || 0) + 1; r.user.verified = true; r.user.devices = [];
  trustDevice(req, res, r.user); saveDb(); setSession(res, r.user);
  res.json({ ok: true });
});

app.post('/api/logout', (req, res) => { res.clearCookie('lumi'); res.json({ ok: true }); });

app.post('/api/password', auth, async (req, res) => {
  if (tooMany('pw:' + req.user.id)) return res.status(429).json({ error: 'Muitas tentativas. Espere alguns minutos.' });
  const current = String(req.body.current || ''), next = String(req.body.next || '');
  if (!(await bcrypt.compare(current, req.user.hash))) return res.status(401).json({ error: 'A senha atual está incorreta.' });
  const weak = weakPassword(next);
  if (weak) return res.status(400).json({ error: weak });
  req.user.hash = await bcrypt.hash(next, 12);
  req.user.tv = (req.user.tv || 0) + 1; // desconecta os outros aparelhos
  req.user.devices = []; trustDevice(req, res, req.user); // só este aparelho continua de confiança
  saveDb(); setSession(res, req.user);
  res.json({ ok: true });
});

app.post('/api/logout-all', auth, (req, res) => {
  req.user.tv = (req.user.tv || 0) + 1; req.user.devices = []; saveDb();
  res.clearCookie('lumi'); res.json({ ok: true });
});

// ---------- Planos de espaço extra (Mercado Pago) ----------
const PLANS = {
  mais50:  { name: '+50 GB',  gb: 50,  price: 3.90 },
  mais100: { name: '+100 GB', gb: 100, price: 6.90 },
  mais256: { name: '+256 GB', gb: 256, price: 12.90 },
};
const MP_TOKEN = process.env.MERCADOPAGO_ACCESS_TOKEN || '';
const PUBLIC_URL = process.env.PUBLIC_URL || (process.env.RAILWAY_PUBLIC_DOMAIN ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}` : '');
console.log(MP_TOKEN ? '[pagamentos] Mercado Pago ATIVADO' : '[pagamentos] Mercado Pago desativado (defina MERCADOPAGO_ACCESS_TOKEN)');

const activePlan = user => (user.plan && PLANS[user.plan] && user.planUntil > Date.now()) ? PLANS[user.plan] : null;
function quotaFor(user) {
  const plan = activePlan(user);
  const base = QUOTA_BYTES + (plan ? plan.gb * 1024 ** 3 : 0);
  return Math.max(base, QUOTA_OVERRIDES.get(user.email) || 0);
}

app.get('/api/plans', auth, (req, res) => {
  const plan = activePlan(req.user);
  res.json({
    payments: !!MP_TOKEN,
    baseGB: Math.round(QUOTA_BYTES / 1024 ** 3),
    current: plan ? { id: req.user.plan, name: plan.name, until: req.user.planUntil } : null,
    plans: Object.entries(PLANS).map(([id, p]) => ({ id, name: p.name, gb: p.gb, price: p.price })),
  });
});

app.post('/api/checkout', auth, async (req, res) => {
  const planId = String(req.body.plan || '');
  const plan = PLANS[planId];
  if (!plan) return res.status(400).json({ error: 'Escolha um plano.' });
  if (!MP_TOKEN) return res.status(503).json({ error: 'Os pagamentos estão sendo ativados. Tente de novo em breve.' });
  if (tooMany('pay:' + req.user.id, 15)) return res.status(429).json({ error: 'Muitas tentativas. Espere alguns minutos.' });
  try {
    const r = await fetch('https://api.mercadopago.com/checkout/preferences', {
      method: 'POST',
      headers: { Authorization: `Bearer ${MP_TOKEN}`, 'Content-Type': 'application/json', 'X-Idempotency-Key': id() },
      body: JSON.stringify({
        items: [{ id: planId, title: `Lumi ${plan.name} por 30 dias`, quantity: 1, currency_id: 'BRL', unit_price: plan.price }],
        payer: { email: req.user.email },
        external_reference: `${req.user.id}:${planId}`,
        notification_url: `${PUBLIC_URL}/api/mp/webhook`,
        back_urls: { success: `${PUBLIC_URL}/?pago=1`, pending: `${PUBLIC_URL}/?pago=2`, failure: `${PUBLIC_URL}/?pago=0` },
        auto_return: 'approved',
        statement_descriptor: 'LUMI',
      }),
    });
    const data = await r.json();
    if (!r.ok || !data.init_point) { console.error('[pagamentos] erro ao criar cobrança', r.status, JSON.stringify(data).slice(0, 300)); throw new Error(); }
    res.json({ url: data.init_point });
  } catch { res.status(502).json({ error: 'Não consegui abrir o pagamento agora. Tente de novo.' }); }
});

// O Mercado Pago avisa aqui quando um pagamento muda; conferimos direto na API deles antes de liberar
app.post('/api/mp/webhook', async (req, res) => {
  res.sendStatus(200);
  if (!MP_TOKEN) return;
  const payId = (req.body && req.body.data && req.body.data.id) || req.query['data.id'] || (req.query.topic === 'payment' && req.query.id);
  if (!payId || !/^\d+$/.test(String(payId))) return;
  try {
    const r = await fetch(`https://api.mercadopago.com/v1/payments/${payId}`, { headers: { Authorization: `Bearer ${MP_TOKEN}` } });
    const p = await r.json();
    if (!r.ok || p.status !== 'approved') return;
    db.payments = db.payments || [];
    if (db.payments.some(x => x.id === String(p.id))) return; // já processado
    const [userId, planId] = String(p.external_reference || '').split(':');
    const user = db.users.find(u => u.id === userId), plan = PLANS[planId];
    if (!user || !plan || Number(p.transaction_amount) + 0.001 < plan.price) return;
    const start = (user.plan === planId && user.planUntil > Date.now()) ? user.planUntil : Date.now();
    user.plan = planId; user.planUntil = start + 30 * 24 * 3600 * 1000;
    db.payments.push({ id: String(p.id), userId, planId, amount: p.transaction_amount, at: Date.now() });
    saveDb();
    console.log('[pagamentos] plano liberado', planId, 'para', userId);
  } catch (e) { console.error('[pagamentos] erro no aviso', e.message); }
});

app.get('/api/me', auth, (req, res) => {
  res.json({ name: req.user.name, email: req.user.email, used: usedBytes(req.user.id), quota: quotaFor(req.user) });
});

// ---------- Arquivos ----------
const upload = multer({
  storage: multer.diskStorage({
    destination: FILES_DIR,
    filename: (req, file, cb) => cb(null, id()),
  }),
  limits: { fileSize: MAX_FILE_BYTES },
});

function kindOf(mime, name) {
  if (mime.startsWith('image/') || /\.(heic|heif)$/i.test(name)) return 'foto';
  if (mime.startsWith('video/')) return 'video';
  if (mime.startsWith('audio/')) return 'audio';
  return 'doc';
}
const publicFile = f => ({ id: f.id, name: f.name, size: f.size, mime: f.mime, kind: f.kind, fav: !!f.fav, createdAt: f.createdAt });

app.get('/api/files', auth, (req, res) => {
  const list = db.files.filter(f => f.userId === req.user.id).sort((a, b) => b.createdAt - a.createdAt);
  res.json(list.map(publicFile));
});

app.post('/api/upload', auth, upload.array('files', 50), (req, res) => {
  const incoming = req.files || [];
  const total = incoming.reduce((s, f) => s + f.size, 0);
  if (usedBytes(req.user.id) + total > quotaFor(req.user)) {
    incoming.forEach(f => fs.unlink(f.path, () => {}));
    return res.status(413).json({ error: 'Seu espaço acabou. Apague alguns arquivos para enviar mais.' });
  }
  const saved = incoming.map(f => {
    // nomes vindos do iPhone chegam em latin1 pelo multer
    const name = Buffer.from(f.originalname, 'latin1').toString('utf8');
    const rec = {
      id: f.filename, userId: req.user.id, name, size: f.size,
      mime: f.mimetype || 'application/octet-stream', kind: kindOf(f.mimetype || '', name),
      fav: false, createdAt: Date.now(),
    };
    db.files.push(rec);
    return publicFile(rec);
  });
  saveDb();
  res.json(saved);
});

// ---------- Armazenamento no Bucket (S3) ----------
const S3_ON = !!(process.env.BUCKET_ENDPOINT && process.env.BUCKET_NAME && process.env.BUCKET_ACCESS_KEY_ID && process.env.BUCKET_SECRET_ACCESS_KEY);
const BUCKET = process.env.BUCKET_NAME;
let s3 = null;
const S3 = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
const { createPresignedPost } = require('@aws-sdk/s3-presigned-post');
if (S3_ON) {
  s3 = new S3.S3Client({
    region: process.env.BUCKET_REGION || 'auto',
    endpoint: process.env.BUCKET_ENDPOINT,
    credentials: { accessKeyId: process.env.BUCKET_ACCESS_KEY_ID, secretAccessKey: process.env.BUCKET_SECRET_ACCESS_KEY },
    requestChecksumCalculation: 'WHEN_REQUIRED', responseChecksumValidation: 'WHEN_REQUIRED',
  });
}
console.log(S3_ON ? `[arquivos] Usando o bucket ${BUCKET}` : '[arquivos] Usando o volume local (bucket não configurado)');

const appOrigins = () => [
  process.env.RAILWAY_PUBLIC_DOMAIN && `https://${process.env.RAILWAY_PUBLIC_DOMAIN}`,
  ...String(process.env.APP_ORIGINS || '').split(',').map(s => s.trim()),
].filter(Boolean);

async function setupBucket() {
  if (!S3_ON) return;
  try {
    await s3.send(new S3.PutBucketCorsCommand({
      Bucket: BUCKET,
      CORSConfiguration: { CORSRules: [{
        AllowedOrigins: appOrigins(), AllowedMethods: ['GET', 'HEAD', 'PUT', 'POST'],
        AllowedHeaders: ['*'], ExposeHeaders: ['ETag'], MaxAgeSeconds: 3000,
      }] },
    }));
    console.log('[arquivos] CORS do bucket configurado para', appOrigins().join(', '));
  } catch (e) { console.error('[arquivos] não consegui configurar o CORS do bucket:', e.name, e.message); }
  // move para o bucket os arquivos que ainda estão no volume
  const local = db.files.filter(f => f.storage !== 's3');
  for (const f of local) {
    const p = path.join(FILES_DIR, f.id);
    if (!fs.existsSync(p)) continue;
    try {
      const key = `u/${f.userId}/${f.id}`;
      await s3.send(new S3.PutObjectCommand({ Bucket: BUCKET, Key: key, Body: fs.createReadStream(p), ContentLength: f.size, ContentType: f.mime }));
      f.storage = 's3'; f.key = key; saveDb();
      fs.unlink(p, () => {});
      console.log('[arquivos] movido para o bucket:', f.id);
    } catch (e) { console.error('[arquivos] falha ao mover', f.id, e.message); }
  }
}

const isRisky = f => /html|svg|xml|javascript|ecmascript/i.test(f.mime) || /\.(html?|svg|xml|js|mjs|xhtml)$/i.test(f.name);
async function signedGet(f, disposition) {
  return getSignedUrl(s3, new S3.GetObjectCommand({
    Bucket: BUCKET, Key: f.key,
    ResponseContentType: isRisky(f) ? 'text/plain; charset=utf-8' : f.mime,
    ResponseContentDisposition: `${disposition}; filename*=UTF-8''${encodeURIComponent(f.name)}`,
  }), { expiresIn: 3600 });
}

// Envio direto do iPhone para o bucket
const pending = new Map(); // id -> { userId, key, name, size, mime, exp }
setInterval(() => { const now = Date.now(); for (const [k, p] of pending) if (p.exp < now) pending.delete(k); }, 10 * 60 * 1000);

app.post('/api/upload/start', auth, async (req, res) => {
  if (!S3_ON) return res.status(400).json({ error: 'Envio direto indisponível.' });
  const list = Array.isArray(req.body.files) ? req.body.files.slice(0, 50) : [];
  if (!list.length) return res.status(400).json({ error: 'Nenhum arquivo escolhido.' });
  const total = list.reduce((s, f) => s + Math.max(0, Number(f.size) || 0), 0);
  if (list.some(f => Number(f.size) > MAX_FILE_BYTES)) return res.status(413).json({ error: `Cada arquivo pode ter no máximo ${Math.round(MAX_FILE_BYTES / 1024 ** 3)} GB.` });
  if (usedBytes(req.user.id) + total > quotaFor(req.user)) return res.status(413).json({ error: 'Seu espaço acabou. Apague alguns arquivos para enviar mais.' });
  try {
    const out = [];
    for (const f of list) {
      const fid = id(), key = `u/${req.user.id}/${fid}`;
      const size = Math.max(0, Number(f.size) || 0);
      const mime = String(f.type || 'application/octet-stream').slice(0, 100);
      const { url, fields } = await createPresignedPost(s3, {
        Bucket: BUCKET, Key: key, Expires: 3 * 3600,
        Fields: { 'Content-Type': mime },
        Conditions: [['eq', '$key', key], ['eq', '$Content-Type', mime], ['content-length-range', 0, size]],
      });
      pending.set(fid, { userId: req.user.id, key, name: String(f.name || 'arquivo').slice(0, 200), size, mime, exp: Date.now() + 3 * 3600 * 1000 });
      out.push({ id: fid, url, fields });
    }
    res.json(out);
  } catch (e) { console.error(e); res.status(500).json({ error: 'Não consegui preparar o envio. Tente de novo.' }); }
});

app.post('/api/upload/finish', auth, async (req, res) => {
  const ids = Array.isArray(req.body.ids) ? req.body.ids.slice(0, 50) : [];
  const saved = [];
  for (const fid of ids) {
    const p = pending.get(String(fid));
    if (!p || p.userId !== req.user.id) continue;
    try {
      const head = await s3.send(new S3.HeadObjectCommand({ Bucket: BUCKET, Key: p.key }));
      const size = Number(head.ContentLength) || 0;
      if (usedBytes(req.user.id) + size > quotaFor(req.user)) {
        await s3.send(new S3.DeleteObjectCommand({ Bucket: BUCKET, Key: p.key })).catch(() => {});
        continue;
      }
      const rec = { id: fid, userId: req.user.id, name: p.name, size, mime: p.mime, kind: kindOf(p.mime, p.name), fav: false, storage: 's3', key: p.key, createdAt: Date.now() };
      db.files.push(rec); saved.push(publicFile(rec));
      pending.delete(fid);
    } catch (e) { console.error('[arquivos] envio não encontrado no bucket', fid, e.name); }
  }
  saveDb();
  res.json(saved);
});

app.get('/api/files/:id/link', auth, async (req, res) => {
  const f = ownFile(req, res); if (!f) return;
  if (f.storage !== 's3') return res.json({ url: `/api/files/${f.id}/view` });
  res.json({ url: await signedGet(f, 'inline') });
});

function ownFile(req, res) {
  const f = db.files.find(x => x.id === req.params.id && x.userId === req.user.id);
  if (!f) res.status(404).json({ error: 'Arquivo não encontrado.' });
  return f;
}

// Visualizar (suporta vídeo com avanço/retrocesso via Range)
app.get('/api/files/:id/view', auth, async (req, res) => {
  const f = ownFile(req, res); if (!f) return;
  if (f.storage === 's3') {
    res.setHeader('Cache-Control', 'private, max-age=1800');
    return res.redirect(302, await signedGet(f, 'inline'));
  }
  // arquivos que poderiam rodar código no navegador são mostrados só como texto
  const risky = isRisky(f);
  res.type(risky ? 'text/plain' : f.mime);
  res.setHeader('Cache-Control', 'private, no-store');
  res.setHeader('Content-Disposition', `inline; filename*=UTF-8''${encodeURIComponent(f.name)}`);
  res.sendFile(path.join(FILES_DIR, f.id));
});

app.get('/api/files/:id/download', auth, async (req, res) => {
  const f = ownFile(req, res); if (!f) return;
  if (f.storage === 's3') { res.setHeader('Cache-Control', 'private, no-store'); return res.redirect(302, await signedGet(f, 'attachment')); }
  res.setHeader('Cache-Control', 'private, no-store');
  res.download(path.join(FILES_DIR, f.id), f.name);
});

app.patch('/api/files/:id', auth, (req, res) => {
  const f = ownFile(req, res); if (!f) return;
  if (typeof req.body.fav === 'boolean') f.fav = req.body.fav;
  if (typeof req.body.name === 'string' && req.body.name.trim()) f.name = req.body.name.trim().slice(0, 200);
  saveDb();
  res.json(publicFile(f));
});

app.delete('/api/files/:id', auth, (req, res) => {
  const f = ownFile(req, res); if (!f) return;
  db.files = db.files.filter(x => x !== f);
  if (f.storage === 's3') s3.send(new S3.DeleteObjectCommand({ Bucket: BUCKET, Key: f.key })).catch(e => console.error('[arquivos] falha ao apagar', f.id, e.message));
  else fs.unlink(path.join(FILES_DIR, f.id), () => {});
  saveDb();
  res.json({ ok: true });
});

app.use((err, req, res, next) => {
  if (err.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ error: 'Arquivo grande demais.' });
  console.error(err);
  res.status(500).json({ error: 'Algo deu errado. Tente de novo.' });
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => { console.log(`Lumi rodando na porta ${PORT} | dados em ${DATA_DIR}`); setupBucket(); });
