const express = require('express');
const basicAuth = require('express-basic-auth');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const fs = require('fs'), path = require('path'), crypto = require('crypto');

const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use((req, res, next) => { res.setHeader('X-Robots-Tag', 'noindex, nofollow'); next(); });
app.use(express.json({ limit: '16kb' }));
app.use(rateLimit({ windowMs: 60 * 1000, max: 120, standardHeaders: true, legacyHeaders: false }));

const SALT = 'bilimall::v1::';
const SUPER_HASH = process.env.SUPER_HASH || '';
const TOTAL = 8;
const DATA = process.env.DATA_DIR || '/data';
const FILE = path.join(DATA, 'state.json');
try { fs.mkdirSync(DATA, { recursive: true }); } catch (e) {}
function readState(){ try { return JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch (e) { return { openDays: [1,2,3,4,5,6,7,8] }; } }
function writeState(s){ fs.writeFileSync(FILE, JSON.stringify(s)); }

// общий замок сайта
app.use(basicAuth({
  users: { [process.env.SITE_USER || 'bilimall']: process.env.SITE_PASS || 'changeme' },
  challenge: true, realm: 'BilimAll'
}));

// читают все авторизованные (обозреватель, суперадмин с любого устройства)
app.get('/api/days', (req, res) => res.json(readState()));

// пишет только суперадмин (проверка его пароля на сервере)
app.post('/api/days', (req, res) => {
  const { openDays, pass } = req.body || {};
  const h = crypto.createHash('sha256').update(SALT + (pass || '')).digest('hex');
  if (!SUPER_HASH || h !== SUPER_HASH) return res.status(403).json({ error: 'forbidden' });
  if (!Array.isArray(openDays)) return res.status(400).json({ error: 'bad' });
  const clean = [...new Set(openDays.filter(d => Number.isInteger(d) && d >= 1 && d <= TOTAL))].sort((a,b)=>a-b);
  writeState({ openDays: clean });
  res.json({ ok: true, openDays: clean });
});

app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.listen(80, () => console.log('bilimall up on 80'));
