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
const QUOTA_BYTES = Number(process.env.QUOTA_MB || 5120) * 1024 * 1024; // 5 GB por pessoa
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
app.use(express.static(path.join(__dirname, 'public')));

function setSession(res, user) {
  const token = jwt.sign({ uid: user.id }, JWT_SECRET, { expiresIn: '60d' });
  res.cookie('lumi', token, {
    httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production',
    maxAge: 60 * 24 * 3600 * 1000,
  });
}
function auth(req, res, next) {
  try {
    const { uid } = jwt.verify(req.cookies.lumi || '', JWT_SECRET);
    const user = db.users.find(u => u.id === uid);
    if (!user) throw new Error();
    req.user = user;
    next();
  } catch {
    res.status(401).json({ error: 'Faça login para continuar.' });
  }
}

// Proteção simples contra tentativa de senha em massa
const attempts = new Map();
function tooMany(key) {
  const now = Date.now();
  const a = attempts.get(key) || { n: 0, t: now };
  if (now - a.t > 15 * 60 * 1000) { a.n = 0; a.t = now; }
  a.n++; attempts.set(key, a);
  return a.n > 20;
}

app.post('/api/register', async (req, res) => {
  if (!ALLOW_SIGNUP) return res.status(403).json({ error: 'Cadastros estão fechados.' });
  const name = String(req.body.name || '').trim().slice(0, 60);
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  if (!name || !/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Preencha nome e um e-mail válido.' });
  if (password.length < 6) return res.status(400).json({ error: 'A senha precisa ter pelo menos 6 caracteres.' });
  if (db.users.some(u => u.email === email)) return res.status(409).json({ error: 'Esse e-mail já tem conta. Entre com ele.' });
  const user = { id: id(), name, email, hash: await bcrypt.hash(password, 10), createdAt: Date.now() };
  db.users.push(user); saveDb();
  setSession(res, user);
  res.json({ ok: true });
});

app.post('/api/login', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  if (tooMany(req.ip + email)) return res.status(429).json({ error: 'Muitas tentativas. Espere alguns minutos.' });
  const user = db.users.find(u => u.email === email);
  if (!user || !(await bcrypt.compare(String(req.body.password || ''), user.hash))) {
    return res.status(401).json({ error: 'E-mail ou senha incorretos.' });
  }
  setSession(res, user);
  res.json({ ok: true });
});

app.post('/api/logout', (req, res) => { res.clearCookie('lumi'); res.json({ ok: true }); });

app.get('/api/me', auth, (req, res) => {
  res.json({ name: req.user.name, email: req.user.email, used: usedBytes(req.user.id), quota: QUOTA_BYTES });
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
  if (usedBytes(req.user.id) + total > QUOTA_BYTES) {
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

function ownFile(req, res) {
  const f = db.files.find(x => x.id === req.params.id && x.userId === req.user.id);
  if (!f) res.status(404).json({ error: 'Arquivo não encontrado.' });
  return f;
}

// Visualizar (suporta vídeo com avanço/retrocesso via Range)
app.get('/api/files/:id/view', auth, (req, res) => {
  const f = ownFile(req, res); if (!f) return;
  res.type(f.mime);
  res.setHeader('Content-Disposition', `inline; filename*=UTF-8''${encodeURIComponent(f.name)}`);
  res.sendFile(path.join(FILES_DIR, f.id));
});

app.get('/api/files/:id/download', auth, (req, res) => {
  const f = ownFile(req, res); if (!f) return;
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
  fs.unlink(path.join(FILES_DIR, f.id), () => {});
  saveDb();
  res.json({ ok: true });
});

app.use((err, req, res, next) => {
  if (err.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ error: 'Arquivo grande demais.' });
  console.error(err);
  res.status(500).json({ error: 'Algo deu errado. Tente de novo.' });
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => console.log(`Lumi rodando na porta ${PORT} | dados em ${DATA_DIR}`));
