const express = require('express');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const fs = require('fs'), path = require('path'), crypto = require('crypto');

const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use((req, res, next) => { res.setHeader('X-Robots-Tag', 'noindex, nofollow'); next(); });
app.use(express.json({ limit: '16kb' }));
app.use(cookieParser());
app.use(rateLimit({ windowMs: 60 * 1000, max: 240, standardHeaders: true, legacyHeaders: false }));

const SALT = 'bilimall::v1::';
const SECRET = process.env.SESS_SECRET || 'dev-secret-change-me';
const USERS = {
  superadmin: { hash: '2333a9b227fe5674c24a0673b051e28e3328dac15284ba8d7e5c2a17ff7f9b12', role: 'super' },
  admin:      { hash: '625e6f2f13d1a10a2d5c4173177e99cbdde8d37961fd26a8c810e75f78ed1185', role: 'admin' }
};
const TOTAL = 8;
const DATA = process.env.DATA_DIR || '/data';
const FILE = path.join(DATA, 'state.json');
try { fs.mkdirSync(DATA, { recursive: true }); } catch (e) {}
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const readState = () => { try { return JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch (e) { return { openDays: [1,2,3,4,5,6,7,8] }; } };
const writeState = s => fs.writeFileSync(FILE, JSON.stringify(s));
function sign(role){ const exp = Date.now() + 1000*60*60*12; const data = role + '.' + exp; return data + '.' + crypto.createHmac('sha256', SECRET).update(data).digest('hex'); }
function verify(tok){ if (!tok) return null; const p = String(tok).split('.'); if (p.length !== 3) return null; const data = p[0] + '.' + p[1]; const good = crypto.createHmac('sha256', SECRET).update(data).digest('hex'); if (p[2] !== good) return null; if (Date.now() > +p[1]) return null; return (p[0] === 'super' || p[0] === 'admin') ? p[0] : null; }
function auth(req, res, next){ const r = verify(req.cookies.ba_sess); if (!r) return res.status(401).json({ error: 'unauth' }); req.role = r; next(); }

const loginLimiter = rateLimit({ windowMs: 15*60*1000, max: 7, standardHeaders: true, legacyHeaders: false, message: { error: 'too_many' } });
app.post('/api/login', loginLimiter, (req, res) => {
  const { user, pass } = req.body || {};
  const u = USERS[String(user || '').trim().toLowerCase()];
  if (!u || sha(SALT + (pass || '')) !== u.hash) return res.status(401).json({ error: 'bad' });
  res.cookie('ba_sess', sign(u.role), { httpOnly: true, secure: true, sameSite: 'lax', maxAge: 1000*60*60*12 });
  res.json({ role: u.role });
});
app.get('/api/me', (req, res) => { const r = verify(req.cookies.ba_sess); if (!r) return res.status(401).json({ error: 'unauth' }); res.json({ role: r }); });
app.post('/api/logout', (req, res) => { res.clearCookie('ba_sess'); res.json({ ok: true }); });

app.get('/api/days', auth, (req, res) => res.json(readState()));
app.post('/api/days', auth, (req, res) => {
  if (req.role !== 'super') return res.status(403).json({ error: 'forbidden' });
  const { openDays } = req.body || {};
  if (!Array.isArray(openDays)) return res.status(400).json({ error: 'bad' });
  const clean = [...new Set(openDays.filter(d => Number.isInteger(d) && d >= 1 && d <= TOTAL))].sort((a,b)=>a-b);
  writeState({ openDays: clean });
  res.json({ ok: true, openDays: clean });
});

const PROFILES = path.join(DATA, 'profiles.json');
const DEF_PROFILES = {
  super: { firstName:'Бекмурат', lastName:'Оналбай', email:'bekmurat@bilimall.kz', phone:'+7 778 965 87 40', org:'ЮКПУ им. О. Жанибекова', notif:{ email:true, weekly:true, newStudents:false }, twofa:false },
  admin: { firstName:'Админ', lastName:'Обозреватель', email:'admin@bilimall.kz', phone:'', org:'', notif:{ email:true, weekly:false, newStudents:false }, twofa:false }
};
const readProfiles = () => { try { return JSON.parse(fs.readFileSync(PROFILES, 'utf8')); } catch (e) { return JSON.parse(JSON.stringify(DEF_PROFILES)); } };
const writeProfiles = p => fs.writeFileSync(PROFILES, JSON.stringify(p));
app.get('/api/profile', auth, (req, res) => { const p = readProfiles(); res.json(p[req.role] || DEF_PROFILES[req.role] || {}); });
app.post('/api/profile', auth, (req, res) => {
  const p = readProfiles();
  if (!p[req.role]) p[req.role] = JSON.parse(JSON.stringify(DEF_PROFILES[req.role] || {}));
  const b = req.body || {};
  ['firstName','lastName','email','phone','org','notif','twofa'].forEach(k => { if (k in b) p[req.role][k] = b[k]; });
  writeProfiles(p);
  res.json({ ok: true });
});

const ACCOUNTS = path.join(DATA, 'accounts.json');
const DEF_ACCOUNTS = [
  { id:1, name:'Бекмурат Оналбай', email:'bekmurat@bilimall.kz', role:'super', lead:true },
  { id:2, name:'Айгерим Сатпаева', email:'aigerim@bilimall.kz', role:'admin' },
  { id:3, name:'Данияр Оспанов', email:'daniyar@bilimall.kz', role:'lead' }
];
const readAccounts = () => { try { return JSON.parse(fs.readFileSync(ACCOUNTS, 'utf8')); } catch (e) { return JSON.parse(JSON.stringify(DEF_ACCOUNTS)); } };
const writeAccounts = a => fs.writeFileSync(ACCOUNTS, JSON.stringify(a));
app.get('/api/accounts', auth, (req, res) => res.json(readAccounts()));
app.post('/api/accounts', auth, (req, res) => {
  if (req.role !== 'super') return res.status(403).json({ error: 'forbidden' });
  const list = (req.body && req.body.accounts) || [];
  if (!Array.isArray(list)) return res.status(400).json({ error: 'bad' });
  const clean = list.filter(a => a && a.name && a.email).slice(0, 500).map(a => ({
    id: Number(a.id) || Date.now() + Math.floor(Math.random() * 1000),
    name: String(a.name).slice(0, 120),
    email: String(a.email).slice(0, 120),
    role: ['super','admin','lead'].includes(a.role) ? a.role : 'lead',
    lead: !!a.lead
  }));
  writeAccounts(clean);
  res.json({ ok: true });
});

app.use('/secure', auth, express.static(path.join(__dirname, 'secure')));
app.use('/lessons', auth, express.static(path.join(__dirname, 'secure', 'lessons')));
app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.listen(80, () => console.log('bilimall v2 up'));
