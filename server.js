'use strict';
// flowers – שרת עצמאי, ללא תלויות חיצוניות. דורש Node 18 ומעלה.
process.env.TZ = process.env.TZ || 'Asia/Jerusalem';
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');

const PORT = +process.env.PORT || 3000;
const DATA = process.env.DATA_DIR || path.join(__dirname, 'data');
// תומך בשני מבנים: קבצי האתר בתיקיית public, או כולם באותה תיקייה (נוח להעלאה מהטלפון)
const FLAT = !fs.existsSync(path.join(__dirname, 'public', 'index.html'));
const PUB = FLAT ? __dirname : path.join(__dirname, 'public');
const FLAT_OK = /^(index\.html|admin\.html|app\.js|admin\.js|style\.css|sw\.js|manifest\.webmanifest|icon[\w.-]*\.(png|svg))$/;
const PRICE = 80;
const FLOWERS = ['ורדים', 'פיוני', 'חמניות', 'טוליפים', 'ליזיאנטוס', 'לבנדר', 'גרברות', 'כלניות'];
const STATUSES = ['ordered', 'pending', 'paid', 'delivered', 'cancelled'];

/* ---------- אחסון (קובץ JSON עם כתיבה אטומית) ---------- */
fs.mkdirSync(DATA, { recursive: true });
const DBF = path.join(DATA, 'db.json');
let db = { customers: [], orders: [], admin: null };
try { db = Object.assign(db, JSON.parse(fs.readFileSync(DBF, 'utf8'))); } catch (e) {}
let timer;
function save() { clearTimeout(timer); timer = setTimeout(flush, 30); }
function flush() { const t = DBF + '.tmp'; fs.writeFileSync(t, JSON.stringify(db)); fs.renameSync(t, DBF); }
process.on('SIGTERM', () => { flush(); process.exit(0); });

let SECRET = process.env.SESSION_SECRET;
if (!SECRET) {
  const f = path.join(DATA, 'secret.txt');
  try { SECRET = fs.readFileSync(f, 'utf8').trim(); }
  catch (e) { SECRET = crypto.randomBytes(32).toString('hex'); fs.writeFileSync(f, SECRET, { mode: 0o600 }); }
}

/* ---------- סיסמאות וטוקנים ---------- */
function hashPw(pw, salt) { salt = salt || crypto.randomBytes(16).toString('hex'); return { salt, hash: crypto.scryptSync(pw, salt, 64).toString('hex') }; }
function checkPw(pw, a) {
  const h = Buffer.from(crypto.scryptSync(String(pw), a.salt, 64).toString('hex')), g = Buffer.from(a.hash);
  return h.length === g.length && crypto.timingSafeEqual(h, g);
}
if (!db.admin) {
  const user = process.env.ADMIN_USER || 'admin', pass = process.env.ADMIN_PASS || crypto.randomBytes(5).toString('hex');
  db.admin = Object.assign({ user }, hashPw(pass)); flush();
  console.log('\n=== נוצר משתמש מנהל ===\nשם משתמש: ' + user + '\nסיסמה:    ' + pass + '\n(אפשר לשנות בעמוד /admin)\n');
}
const b64 = s => Buffer.from(s).toString('base64url');
function sign(o) { const p = b64(JSON.stringify(o)); return p + '.' + crypto.createHmac('sha256', SECRET).update(p).digest('base64url'); }
function verify(t) {
  if (!t) return null;
  const [p, s] = t.split('.'); if (!p || !s) return null;
  const e = crypto.createHmac('sha256', SECRET).update(p).digest('base64url');
  if (e.length !== s.length || !crypto.timingSafeEqual(Buffer.from(e), Buffer.from(s))) return null;
  try { const o = JSON.parse(Buffer.from(p, 'base64url').toString()); return o.exp > Date.now() ? o : null; } catch (e) { return null; }
}
function cookies(req) { const o = {}; (req.headers.cookie || '').split(';').forEach(c => { const i = c.indexOf('='); if (i > 0) o[c.slice(0, i).trim()] = c.slice(i + 1).trim(); }); return o; }
function setCookie(req, res, name, val, age) {
  const sec = req.headers['x-forwarded-proto'] === 'https' || process.env.FORCE_SECURE;
  res.setHeader('Set-Cookie', [].concat(res.getHeader('Set-Cookie') || [], `${name}=${val}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${age}${sec ? '; Secure' : ''}`));
}
const getCust = req => { const t = verify(cookies(req).fc); return t && db.customers.find(c => c.id === t.c); };
const isAdmin = req => { const t = verify(cookies(req).fa); return !!t && t.s === db.admin.salt; };
const logCust = (req, res, c) => setCookie(req, res, 'fc', sign({ c: c.id, exp: Date.now() + 365 * 864e5 }), 365 * 86400);

/* ---------- הגבלת ניסיונות ---------- */
const hits = new Map();
function limited(req, key, max) {
  const k = key + (req.headers['x-forwarded-for'] || req.socket.remoteAddress), n = Date.now(), h = hits.get(k) || { n: 0, t: n };
  if (n - h.t > 6e5) { h.n = 0; h.t = n; }
  h.n++; hits.set(k, h); return h.n > max;
}

/* ---------- הודעות (מייל ו-SMS, אופציונלי לפי משתני סביבה) ---------- */
async function sendMail(to, subject, html) {
  if (!to) return;
  if (!process.env.RESEND_API_KEY || !process.env.MAIL_FROM) { console.log('[מייל לא מוגדר] ל:', to, '|', subject); return; }
  try {
    const r = await fetch('https://api.resend.com/emails', { method: 'POST', headers: { Authorization: 'Bearer ' + process.env.RESEND_API_KEY, 'Content-Type': 'application/json' }, body: JSON.stringify({ from: process.env.MAIL_FROM, to: [to], subject, html }) });
    if (!r.ok) console.log('שליחת מייל נכשלה', r.status, await r.text());
  } catch (e) { console.log('שליחת מייל נכשלה', e.message); }
}
async function notifyAdmin(text) {
  console.log('[התראה למנהל]', text);
  const { TWILIO_SID: sid, TWILIO_TOKEN: tok, TWILIO_FROM: from, ADMIN_PHONE: to } = process.env;
  if (!sid || !tok || !from || !to) return;
  const dest = to.startsWith('+') ? to : '+972' + to.replace(/^0/, '');
  try {
    const r = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${sid}/Messages.json`, { method: 'POST', headers: { Authorization: 'Basic ' + Buffer.from(sid + ':' + tok).toString('base64'), 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ To: dest, From: from, Body: text }) });
    if (!r.ok) console.log('שליחת SMS נכשלה', r.status, await r.text());
  } catch (e) { console.log('שליחת SMS נכשלה', e.message); }
}
const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const mailWrap = (t, p) => `<div dir="rtl" style="font-family:Arial,sans-serif;max-width:480px;margin:auto;padding:24px;border:1px solid #eee;border-radius:16px"><h2 style="color:#d63a72;margin:0 0 12px">flowers 🌸</h2><h3>${t}</h3><p style="line-height:1.6">${p}</p></div>`;

/* ---------- ולידציה ועזרים ---------- */
const norm = p => String(p || '').replace(/[\s-]/g, '');
const okPhone = p => /^0\d{8,9}$/.test(p);
const okMail = e => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e) && e.length < 120;
const clean = (s, n) => String(s == null ? '' : s).trim().slice(0, n);
function vCust(b) {
  const o = { name: clean(b.name, 60), phone: norm(b.phone), email: clean(b.email, 120).toLowerCase(), addr: clean(b.addr, 150) }, e = {};
  if (o.name.length < 2) e.name = 'נא להזין שם מלא';
  if (!okPhone(o.phone)) e.phone = 'נא להזין מספר טלפון תקין, למשל 050-1234567';
  if (!okMail(o.email)) e.email = 'נא להזין כתובת מייל תקינה';
  if (o.addr.length < 5) e.addr = 'נא להזין כתובת למשלוח';
  return { o, e, bad: !!Object.keys(e).length };
}
const ymd = d => d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
function nextDelivery() {
  const d = new Date(); d.setHours(9, 0, 0, 0);
  do { d.setDate(d.getDate() + 1); } while (d.getDay() !== 5);
  if (d - new Date() < 172800000) d.setDate(d.getDate() + 7);
  return ymd(d);
}
function active(c) {
  const today = ymd(new Date());
  return db.orders.filter(o => o.cid === c.id && (o.status === 'pending' || o.status === 'paid' || (o.status === 'ordered' && o.date >= today))).sort((a, b) => a.date < b.date ? -1 : 1)[0];
}
const daysUntil = d => Math.round((new Date(d + 'T00:00:00') - new Date(ymd(new Date()) + 'T00:00:00')) / 864e5);
const eff = o => (o.status === 'paid' && o.date < ymd(new Date())) ? 'delivered' : o.status;
const pubOrder = c => { const o = active(c); return o ? { date: o.date, flower: o.flower, addr: o.addr, status: o.status, ref: o.ref, canCancel: daysUntil(o.date) >= 3 } : { date: nextDelivery(), flower: FLOWERS[0], addr: c.addr, status: 'draft', ref: null, canCancel: false }; };
const pubCust = c => ({ name: c.name, phone: c.phone, email: c.email, addr: c.addr });
const newRef = () => { let r; do { r = 'פ-' + (1000 + crypto.randomInt(9000)); } while (db.orders.some(o => o.ref === r)); return r; };
const uid = () => crypto.randomBytes(8).toString('hex');

/* ---------- HTTP ---------- */
class HttpError extends Error { constructor(code, msg, fields) { super(msg); this.code = code; this.fields = fields; } }
function send(res, code, obj) { res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(obj)); }
function body(req) {
  return new Promise((ok, no) => {
    if (!/application\/json/.test(req.headers['content-type'] || '')) return no(new HttpError(415, 'סוג בקשה לא נתמך'));
    let d = ''; req.on('data', c => { d += c; if (d.length > 20000) { no(new HttpError(413, 'הבקשה גדולה מדי')); req.destroy(); } });
    req.on('end', () => { try { ok(d ? JSON.parse(d) : {}); } catch (e) { no(new HttpError(400, 'בקשה לא תקינה')); } });
  });
}
const needCust = req => { const c = getCust(req); if (!c) throw new HttpError(401, 'נדרשת התחברות'); return c; };
const needAdmin = req => { if (!isAdmin(req)) throw new HttpError(401, 'נדרשת התחברות מנהל'); };
const adminRow = o => { const c = db.customers.find(x => x.id === o.cid) || {}; return { id: o.id, date: o.date, flower: o.flower, addr: o.addr, status: o.status, ref: o.ref, refund: o.refund || null, customer: { name: c.name || '', phone: c.phone || '', email: c.email || '' } }; };

async function api(req, res, p) {
  const m = req.method;
  /* --- לקוחות --- */
  if (p === '/api/register' && m === 'POST') {
    if (limited(req, 'reg', 10)) throw new HttpError(429, 'יותר מדי ניסיונות, נסו שוב בעוד כמה דקות');
    const v = vCust(await body(req)); if (v.bad) throw new HttpError(400, 'פרטים חסרים', v.e);
    let c = db.customers.find(x => x.phone === v.o.phone);
    if (c) throw new HttpError(409, 'כבר קיים חשבון עם הטלפון הזה. אפשר להיכנס.', { phone: 'כבר קיים חשבון עם הטלפון הזה, בחרו "יש לי כבר חשבון"' });
    c = Object.assign({ id: uid(), created: Date.now() }, v.o); db.customers.push(c); save();
    logCust(req, res, c);
    sendMail(c.email, 'ברוכים הבאים ל־flowers', mailWrap('נרשמתם בהצלחה, ' + esc(c.name), 'שמחים שהצטרפתם! אפשר להיכנס לאפליקציה, לבחור פרחים ולהזמין את הזר הראשון שלכם.'));
    notifyAdmin('לקוח/ה חדש/ה נרשם/ה: ' + c.name + ' ' + c.phone);
    return send(res, 200, { customer: pubCust(c), order: pubOrder(c) });
  }
  if (p === '/api/login' && m === 'POST') {
    if (limited(req, 'login', 10)) throw new HttpError(429, 'יותר מדי ניסיונות, נסו שוב בעוד כמה דקות');
    const b = await body(req), c = db.customers.find(x => x.phone === norm(b.phone) && x.email === clean(b.email, 120).toLowerCase());
    if (!c) throw new HttpError(401, 'לא נמצא חשבון עם הפרטים האלה. אפשר ליצור חשבון חדש.');
    logCust(req, res, c); return send(res, 200, { customer: pubCust(c), order: pubOrder(c) });
  }
  if (p === '/api/logout' && m === 'POST') { setCookie(req, res, 'fc', '', 0); return send(res, 200, {}); }
  if (p === '/api/me' && m === 'GET') { const c = needCust(req); return send(res, 200, { customer: pubCust(c), order: pubOrder(c) }); }
  if (p === '/api/me' && m === 'PUT') {
    const c = needCust(req), v = vCust(await body(req)); if (v.bad) throw new HttpError(400, 'פרטים חסרים', v.e);
    if (db.customers.some(x => x.id !== c.id && x.phone === v.o.phone)) throw new HttpError(409, 'הטלפון כבר רשום', { phone: 'הטלפון כבר רשום בחשבון אחר' });
    Object.assign(c, v.o); save(); return send(res, 200, { customer: pubCust(c), order: pubOrder
