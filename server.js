require('dotenv').config();
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

if (!process.env.DATABASE_URL) { console.error('Missing DATABASE_URL (Supabase Postgres connection string)'); process.exit(1); }
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: process.env.DB_SSL_REJECT_UNAUTHORIZED !== 'false' }, max: 10 });
const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '20kb' }));
app.use('/api/', rateLimit({ windowMs: 60_000, limit: 120, standardHeaders: 'draft-7', legacyHeaders: false }));
const cookieName = 'ecoloop_session';
const hashToken = token => crypto.createHash('sha256').update(token).digest('hex');
const validRole = role => ['student', 'merchant'].includes(role);
const validId = id => /^\d{5,20}$/.test(String(id || ''));
const publicUser = u => ({ id: u.public_id, role: u.role, name: u.name || u.public_id, profileType: u.role === 'student' ? 'นักศึกษา' : 'ร้านค้า' });
const query = (sql, params = []) => pool.query(sql, params);
const cookieOptions = { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict', path: '/', maxAge: 7 * 86400000 };
function cookies(req) { return Object.fromEntries((req.headers.cookie || '').split(';').map(s => { const p=s.trim().indexOf('='); return p < 0 ? [] : [s.trim().slice(0,p), s.trim().slice(p+1)]; }).filter(x => x.length === 2)); }
async function setSession(res, userId) {
  const token = crypto.randomBytes(32).toString('hex');
  await query('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES($1,$2,$3)', [hashToken(token),userId,Date.now()+7*86400000]);
  res.cookie(cookieName, token, cookieOptions);
}
async function auth(req,res,next) {
  try {
    const token = cookies(req)[cookieName];
    if (!token || !/^[a-f0-9]{64}$/.test(token)) return res.status(401).json({error:'กรุณาเข้าสู่ระบบก่อน'});
    const {rows} = await query('SELECT u.id,u.public_id,u.role,u.name FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>$2', [hashToken(token),Date.now()]);
    if (!rows.length) { res.clearCookie(cookieName,{path:'/'}); return res.status(401).json({error:'เซสชันหมดอายุ กรุณาเข้าสู่ระบบใหม่'}); }
    req.user=rows[0]; next();
  } catch(e) { next(e); }
}
const requireRole = role => (req,res,next) => req.user.role === role ? next() : res.status(403).json({error:'ไม่มีสิทธิ์ใช้งานส่วนนี้'});
app.post('/api/register', async (req,res,next) => {
  try {
    const {id,password,role,name}=req.body || {};
    if (!validId(id) || !validRole(role) || typeof password !== 'string' || password.length < 6 || password.length > 128 || typeof name !== 'string' || name.trim().length < 2 || name.trim().length > 100) return res.status(400).json({error:'กรอกรหัสตัวเลข 5–20 หลัก ชื่อ 2–100 ตัวอักษร และรหัสผ่าน 6–128 ตัวอักษร'});
    const hash=await bcrypt.hash(password,12);
    const {rows}=await query('INSERT INTO users(public_id,role,password_hash,name) VALUES($1,$2,$3,$4) RETURNING id,public_id,role,name',[String(id),role,hash,name.trim()]);
    await setSession(res,rows[0].id);
    res.json({user:publicUser(rows[0])});
  } catch(e) { if(e.code==='23505') return res.status(409).json({error:'รหัสนี้สมัครบัญชีประเภทนี้ไว้แล้ว กรุณาเข้าสู่ระบบ'}); next(e); }
});
app.post('/api/login', async(req,res,next)=>{
  try {
    const {id,password,role}=req.body || {};
    if(!validId(id)||!validRole(role)||typeof password!=='string') return res.status(400).json({error:'ข้อมูลเข้าสู่ระบบไม่ถูกต้อง'});
    const {rows}=await query('SELECT * FROM users WHERE public_id=$1 AND role=$2',[String(id),role]);
    if(!rows.length || !(await bcrypt.compare(password,rows[0].password_hash))) return res.status(401).json({error:'ไม่พบบัญชีหรือรหัสผ่านไม่ถูกต้อง หากยังไม่มีบัญชีให้กดสมัครบัญชีใหม่'});
    await setSession(res,rows[0].id); res.json({user:publicUser(rows[0])});
  } catch(e) {next(e);}
});
app.get('/api/me',auth,(req,res)=>res.json({user:publicUser(req.user)}));
app.post('/api/logout',async(req,res,next)=>{try{const token=cookies(req)[cookieName]; if(token) await query('DELETE FROM sessions WHERE token_hash=$1',[hashToken(token)]); res.clearCookie(cookieName,{path:'/'});res.json({ok:true});}catch(e){next(e);}});
app.post('/api/codes',auth,requireRole('student'),async(req,res,next)=>{
  const client=await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('UPDATE verification_codes SET used_at=$1 WHERE student_user_id=$2 AND used_at IS NULL',[Date.now(),req.user.id]);
    let code;
    for(let attempt=0;attempt<10;attempt++) {
      code=String(crypto.randomInt(100000,1000000));
      const r=await client.query('INSERT INTO verification_codes(code,student_user_id,expires_at) VALUES($1,$2,$3) ON CONFLICT DO NOTHING RETURNING code',[code,req.user.id,Date.now()+60000]);
      if(r.rowCount) break;
      code=null;
    }
    if(!code) throw new Error('Unable to generate unique code');
    await client.query('COMMIT');
    res.json({code,expires_at:new Date(Date.now()+60000).toISOString()});
  } catch(e) {await client.query('ROLLBACK');next(e);}finally{client.release();}
});
app.post('/api/codes/lookup',auth,requireRole('merchant'),async(req,res,next)=>{
  try {
    const code=String(req.body?.code||''); if(!/^\d{6}$/.test(code)) return res.status(400).json({error:'กรุณากรอกรหัส 6 หลัก'});
    const {rows}=await query('SELECT u.public_id AS student_id FROM verification_codes v JOIN users u ON u.id=v.student_user_id WHERE v.code=$1 AND v.used_at IS NULL AND v.expires_at>$2',[code,Date.now()]);
    if(!rows.length) return res.status(404).json({error:'ไม่พบรหัส รหัสหมดอายุ หรือถูกใช้ไปแล้ว'});
    res.json(rows[0]);
  } catch(e){next(e);}
});
app.post('/api/codes/confirm',auth,requireRole('merchant'),async(req,res,next)=>{
  if(req.body?.observed!==true) return res.status(400).json({error:'กรุณายืนยันว่าเห็นการใช้แก้วส่วนตัวจริง'});
  const code=String(req.body?.code||''); if(!/^\d{6}$/.test(code)) return res.status(400).json({error:'รหัสไม่ถูกต้อง'});
  const client=await pool.connect();
  try {
    await client.query('BEGIN');
    const r=await client.query('UPDATE verification_codes SET used_at=$1 WHERE code=$2 AND used_at IS NULL AND expires_at>$1 RETURNING student_user_id',[Date.now(),code]);
    if(!r.rowCount) {await client.query('ROLLBACK');return res.status(409).json({error:'รหัสหมดอายุหรือถูกใช้ไปแล้ว'});}
    await client.query('INSERT INTO transactions(student_user_id,merchant_user_id) VALUES($1,$2)',[r.rows[0].student_user_id,req.user.id]);
    await client.query('COMMIT');res.json({ok:true,points_awarded:100});
  }catch(e){await client.query('ROLLBACK');next(e);}finally{client.release();}
});
app.get('/api/dashboard',auth,async(req,res,next)=>{
  try {
    if(req.user.role==='student') {
      const [tx,active,stats]=await Promise.all([
        query('SELECT t.id,t.created_at,m.public_id AS merchant_id FROM transactions t JOIN users m ON m.id=t.merchant_user_id WHERE t.student_user_id=$1 ORDER BY t.id DESC LIMIT 100',[req.user.id]),
        query('SELECT code,expires_at FROM verification_codes WHERE student_user_id=$1 AND used_at IS NULL AND expires_at>$2 ORDER BY expires_at DESC LIMIT 1',[req.user.id,Date.now()]),
        query('SELECT COUNT(*)::int AS cups, (COUNT(*)*100)::int AS points FROM transactions WHERE student_user_id=$1',[req.user.id])]);
      res.json({user:publicUser(req.user),transactions:tx.rows,stats:stats.rows[0],activeCode:active.rows.length?{code:active.rows[0].code,expires_at:new Date(Number(active.rows[0].expires_at)).toISOString()}:null});
    } else {
      const [tx,today]=await Promise.all([
        query('SELECT t.id,t.created_at,s.public_id AS student_id FROM transactions t JOIN users s ON s.id=t.student_user_id WHERE t.merchant_user_id=$1 ORDER BY t.id DESC LIMIT 100',[req.user.id]),
        query("SELECT COUNT(*)::int AS today FROM transactions WHERE merchant_user_id=$1 AND (created_at AT TIME ZONE 'Asia/Bangkok')::date=(NOW() AT TIME ZONE 'Asia/Bangkok')::date",[req.user.id])]);
      res.json({user:publicUser(req.user),transactions:tx.rows,stats:today.rows[0]});
    }
  }catch(e){next(e);}
});
app.get('/api/health', async (req,res) => { try { await query('SELECT 1'); res.json({ok:true,database:'connected'}); } catch(e) { console.error('Health check:',e.message); res.status(503).json({ok:false,database:'unavailable'}); } });
app.use(express.static(path.join(__dirname,'public')));
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.use((err,req,res,next)=>{console.error('API error:',err);if(!res.headersSent)res.status(500).json({error:'เกิดข้อผิดพลาดของเซิร์ฟเวอร์ กรุณาลองใหม่'});});
const PORT=process.env.PORT||3000;
pool.query('SELECT 1').then(()=>app.listen(PORT,()=>console.log(`EcoLoop + Supabase PostgreSQL running on port ${PORT}`))).catch(e=>{console.error('Supabase connection failed:',e.message);process.exit(1);});
