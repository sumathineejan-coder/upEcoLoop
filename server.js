const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new Database(path.join(DATA_DIR, 'ecoloop.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 public_id TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('student','merchant')),
 password_hash TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT (datetime('now')),
 UNIQUE(public_id, role)
);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id);
CREATE TABLE IF NOT EXISTS verification_codes (
 code TEXT PRIMARY KEY,
 student_user_id INTEGER NOT NULL REFERENCES users(id),
 expires_at INTEGER NOT NULL,
 used_at INTEGER,
 created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS codes_student_idx ON verification_codes(student_user_id);
CREATE TABLE IF NOT EXISTS transactions (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 student_user_id INTEGER NOT NULL REFERENCES users(id),
 merchant_user_id INTEGER NOT NULL REFERENCES users(id),
 created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS tx_student_idx ON transactions(student_user_id, id DESC);
CREATE INDEX IF NOT EXISTS tx_merchant_idx ON transactions(merchant_user_id, id DESC);
`);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '20kb' }));
app.use('/api/', rateLimit({ windowMs: 60_000, limit: 120, standardHeaders: 'draft-7', legacyHeaders: false }));
const cookieName = 'ecoloop_session';
const hashToken = token => crypto.createHash('sha256').update(token).digest('hex');
function setSession(res, userId) {
  const token = crypto.randomBytes(32).toString('hex');
  const expires = Date.now() + 7 * 24 * 60 * 60 * 1000;
  db.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').run(hashToken(token), userId, expires);
  res.cookie(cookieName, token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict', path: '/', maxAge: 7 * 24 * 60 * 60 * 1000 });
}
function auth(req, res, next) {
  const token = req.cookies?.[cookieName];
  if (!token) return res.status(401).json({ error: 'กรุณาเข้าสู่ระบบก่อน' });
  const row = db.prepare(`SELECT u.id,u.public_id,u.role,s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?`).get(hashToken(token));
  if (!row || row.expires_at < Date.now()) {
    if (token) db.prepare('DELETE FROM sessions WHERE token_hash=?').run(hashToken(token));
    res.clearCookie(cookieName, { path: '/' });
    return res.status(401).json({ error: 'เซสชันหมดอายุ กรุณาเข้าสู่ระบบใหม่' });
  }
  req.user = { dbId: row.id, id: row.public_id, role: row.role };
  next();
}
const requireRole = role => (req,res,next) => req.user.role === role ? next() : res.status(403).json({error:'ไม่มีสิทธิ์ใช้งานส่วนนี้'});
function publicUser(u) { return { id: u.id, role: u.role }; }
app.use((req,res,next)=>{ // lightweight cookie parser
  req.cookies = {};
  (req.headers.cookie || '').split(';').forEach(part => { const i=part.indexOf('='); if(i>0) req.cookies[part.slice(0,i).trim()] = decodeURIComponent(part.slice(i+1).trim()); });
  next();
});
app.post('/api/register', async (req,res) => {
  const { id, password, role } = req.body || {};
  if (!/^\d{5,20}$/.test(String(id || '')) || typeof password !== 'string' || password.length < 6 || password.length > 128 || !['student','merchant'].includes(role)) return res.status(400).json({error:'กรอกรหัสตัวเลข 5–20 หลัก และรหัสผ่าน 6–128 ตัวอักษร'});
  try {
    const result = db.prepare('INSERT INTO users(public_id,role,password_hash) VALUES(?,?,?)').run(String(id), role, await bcrypt.hash(password, 12));
    setSession(res, Number(result.lastInsertRowid));
    res.json({ user: { id: String(id), role } });
  } catch (e) { if (String(e.message).includes('UNIQUE')) return res.status(409).json({error:'รหัสนี้สมัครบัญชีประเภทนี้ไว้แล้ว กรุณาเข้าสู่ระบบ'}); res.status(500).json({error:'ไม่สามารถสร้างบัญชีได้'}); }
});
app.post('/api/login', async (req,res) => {
  const { id, password, role } = req.body || {};
  if (!/^\d{5,20}$/.test(String(id || '')) || typeof password !== 'string' || !['student','merchant'].includes(role)) return res.status(400).json({error:'ข้อมูลเข้าสู่ระบบไม่ถูกต้อง'});
  const row = db.prepare('SELECT * FROM users WHERE public_id=? AND role=?').get(String(id), role);
  if (!row || !(await bcrypt.compare(password, row.password_hash))) return res.status(401).json({error:'ไม่พบบัญชีหรือรหัสผ่านไม่ถูกต้อง หากยังไม่มีบัญชีให้กดสมัครบัญชีใหม่'});
  setSession(res, row.id);
  res.json({user:{id:row.public_id,role:row.role}});
});
app.get('/api/me', auth, (req,res)=>res.json({user:publicUser(req.user)}));
app.post('/api/logout', (req,res)=>{const token=req.cookies?.[cookieName];if(token)db.prepare('DELETE FROM sessions WHERE token_hash=?').run(hashToken(token));res.clearCookie(cookieName,{path:'/'});res.json({ok:true})});
app.post('/api/codes', auth, requireRole('student'), (req,res)=>{
  db.prepare('UPDATE verification_codes SET used_at=? WHERE student_user_id=? AND used_at IS NULL').run(Date.now(),req.user.dbId);
  let code; do { code=String(crypto.randomInt(100000,1000000)); } while(db.prepare('SELECT 1 FROM verification_codes WHERE code=?').get(code));
  const expires=Date.now()+60_000;
  db.prepare('INSERT INTO verification_codes(code,student_user_id,expires_at) VALUES(?,?,?)').run(code,req.user.dbId,expires);
  res.json({code,expires_at:new Date(expires).toISOString()});
});
app.post('/api/codes/lookup', auth, requireRole('merchant'), (req,res)=>{
  const code=String(req.body?.code||'');
  if(!/^\d{6}$/.test(code))return res.status(400).json({error:'กรุณากรอกรหัส 6 หลัก'});
  const row=db.prepare(`SELECT v.*,u.public_id AS student_id FROM verification_codes v JOIN users u ON u.id=v.student_user_id WHERE v.code=?`).get(code);
  if(!row||row.used_at||row.expires_at<=Date.now())return res.status(404).json({error:'ไม่พบรหัส รหัสหมดอายุ หรือถูกใช้ไปแล้ว'});
  res.json({student_id:row.student_id});
});
const confirmCode = db.transaction((code, merchantId) => {
  const row=db.prepare('SELECT * FROM verification_codes WHERE code=?').get(code);
  if(!row||row.used_at||row.expires_at<=Date.now())return false;
  const changed=db.prepare('UPDATE verification_codes SET used_at=? WHERE code=? AND used_at IS NULL AND expires_at>?').run(Date.now(),code,Date.now()).changes;
  if(!changed)return false;
  db.prepare('INSERT INTO transactions(student_user_id,merchant_user_id) VALUES(?,?)').run(row.student_user_id,merchantId);
  return true;
});
app.post('/api/codes/confirm', auth, requireRole('merchant'), (req,res)=>{
  const code=String(req.body?.code||'');
  if(req.body?.observed!==true)return res.status(400).json({error:'กรุณายืนยันว่าเห็นการใช้แก้วส่วนตัวจริง'});
  if(!/^\d{6}$/.test(code))return res.status(400).json({error:'รหัสไม่ถูกต้อง'});
  try { if(!confirmCode(code,req.user.dbId))return res.status(409).json({error:'รหัสหมดอายุหรือถูกใช้ไปแล้ว'}); res.json({ok:true,points_awarded:100}); }
  catch(e){res.status(500).json({error:'บันทึกรายการไม่สำเร็จ'})}
});
app.get('/api/dashboard', auth, (req,res)=>{
  if(req.user.role==='student'){
    const tx=db.prepare(`SELECT t.id,t.created_at,m.public_id AS merchant_id FROM transactions t JOIN users m ON m.id=t.merchant_user_id WHERE t.student_user_id=? ORDER BY t.id DESC LIMIT 100`).all(req.user.dbId);
    const active=db.prepare('SELECT code,expires_at FROM verification_codes WHERE student_user_id=? AND used_at IS NULL AND expires_at>? ORDER BY expires_at DESC LIMIT 1').get(req.user.dbId,Date.now());
    res.json({transactions:tx,stats:{cups:db.prepare('SELECT COUNT(*) AS n FROM transactions WHERE student_user_id=?').get(req.user.dbId).n,points:db.prepare('SELECT COUNT(*)*100 AS n FROM transactions WHERE student_user_id=?').get(req.user.dbId).n},activeCode:active?{code:active.code,expires_at:new Date(active.expires_at).toISOString()}:null});
  } else {
    const tx=db.prepare(`SELECT t.id,t.created_at,s.public_id AS student_id FROM transactions t JOIN users s ON s.id=t.student_user_id WHERE t.merchant_user_id=? ORDER BY t.id DESC LIMIT 100`).all(req.user.dbId);
    const today=db.prepare(`SELECT COUNT(*) AS n FROM transactions WHERE merchant_user_id=? AND date(created_at,'localtime')=date('now','localtime')`).get(req.user.dbId).n;
    res.json({transactions:tx,stats:{today}});
  }
});
app.use(express.static(path.join(__dirname,'public')));
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.listen(PORT,()=>console.log(`EcoLoop server running on port ${PORT}`));
