const express = require("express"), Database = require("better-sqlite3"), bcrypt = require("bcryptjs"), crypto = require("crypto"), path = require("path");
const TZ = process.env.TZ_NAME || "Asia/Kolkata", OFFSET = process.env.TZ_OFFSET || "+05:30", PORT = process.env.PORT || 3000;
const SECTIONS = ["Bhopal", "RKMP", "Nishatpura", "DRM Office"];
const db = new Database(process.env.DB_PATH || path.join(__dirname, "data.db"));
db.pragma("journal_mode=WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, emp_id TEXT UNIQUE NOT NULL, name TEXT NOT NULL, pin_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'employee', section TEXT, rest INTEGER, since TEXT, left_on TEXT);
CREATE TABLE IF NOT EXISTS att(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, date TEXT NOT NULL, in_at INTEGER, out_at INTEGER, UNIQUE(user_id, date));
CREATE TABLE IF NOT EXISTS offs(user_id INTEGER NOT NULL, date TEXT NOT NULL, status TEXT NOT NULL, PRIMARY KEY(user_id, date));
CREATE TABLE IF NOT EXISTS sess(tok TEXT PRIMARY KEY, user_id INTEGER NOT NULL, exp INTEGER NOT NULL);`);

const today = () => new Date().toLocaleDateString("en-CA", { timeZone: TZ });
const dow = d => new Date(d + "T00:00:00Z").getUTCDay();
const ms = (d, t) => /^\d\d:\d\d$/.test(t || "") ? Date.parse(`${d}T${t}:00${OFFSET}`) : null;
const pub = u => ({ id: u.id, empId: u.emp_id, name: u.name, role: u.role, section: u.section });

if (!db.prepare("SELECT 1 FROM users WHERE role='admin'").get()) {
  const id = process.env.ADMIN_ID || "admin", pin = process.env.ADMIN_PIN || String(crypto.randomInt(100000, 999999));
  db.prepare("INSERT INTO users(emp_id,name,pin_hash,role) VALUES(?,?,?,'admin')").run(id, "Admin", bcrypt.hashSync(pin, 10));
  console.log(`First run. Admin login -> ID: ${id}  PIN: ${pin}  (change it from the Staff tab)`);
}

// P present, R rest, L leave, A absent, "" not counted (future, today-not-in, before joining, after leaving)
function stat(u, date, rec, off, tod) {
  if ((u.since && date < u.since) || (u.left_on && date >= u.left_on)) return "";
  if (rec) return "P";
  if (off) return off.status === "leave" ? "L" : "R";
  if (u.rest != null && dow(date) === u.rest) return "R";
  return date < tod ? "A" : "";
}

function month(mon) {
  const [y, m] = mon.split("-").map(Number), dim = new Date(y, m, 0).getDate(), tod = today(), a = mon + "-01", b = mon + "-31";
  const att = db.prepare("SELECT * FROM att WHERE date BETWEEN ? AND ?").all(a, b), offs = db.prepare("SELECT * FROM offs WHERE date BETWEEN ? AND ?").all(a, b);
  const users = db.prepare("SELECT * FROM users WHERE role='employee'").all()
    .filter(u => !(u.left_on && u.left_on <= a) && !(u.since && u.since > b))
    .sort((x, y) => SECTIONS.indexOf(x.section) - SECTIONS.indexOf(y.section) || x.name.localeCompare(y.name));
  return users.map(u => {
    const cells = [], t = { P: 0, R: 0, L: 0, A: 0, h: 0 };
    for (let d = 1; d <= dim; d++) {
      const ds = `${mon}-${String(d).padStart(2, "0")}`;
      const r = att.find(x => x.user_id === u.id && x.date === ds), o = offs.find(x => x.user_id === u.id && x.date === ds);
      const k = stat(u, ds, r, o, tod); cells.push(k); if (k) t[k]++;
      if (r && r.in_at && r.out_at) t.h += (r.out_at - r.in_at) / 36e5;
    }
    return { u, cells, t };
  });
}

const app = express();
app.set("trust proxy", 1);
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

function auth(req, res, next) {
  const m = /(?:^|; )sid=([^;]+)/.exec(req.headers.cookie || "");
  const u = m && db.prepare("SELECT u.* FROM sess s JOIN users u ON u.id=s.user_id WHERE s.tok=? AND s.exp>?").get(m[1], Date.now());
  if (!u || (u.left_on && u.left_on <= today())) return res.status(401).json({ error: "Please sign in" });
  req.u = u; next();
}
const admin = (req, res, next) => req.u.role === "admin" ? next() : res.status(403).json({ error: "Admin only" });

const fails = new Map();
app.post("/api/login", (req, res) => {
  const { empId, pin } = req.body || {}, k = req.ip + "|" + String(empId).toLowerCase(), f = fails.get(k) || { n: 0, t: 0 };
  if (f.n >= 5 && Date.now() - f.t < 6e5) return res.status(429).json({ error: "Too many wrong attempts. Try again in 10 minutes." });
  const u = db.prepare("SELECT * FROM users WHERE lower(emp_id)=lower(?)").get(String(empId || ""));
  if (!u || (u.left_on && u.left_on <= today()) || !bcrypt.compareSync(String(pin || ""), u.pin_hash)) {
    fails.set(k, { n: f.n + 1, t: Date.now() }); return res.status(401).json({ error: "Wrong ID or PIN" });
  }
  fails.delete(k);
  const tok = crypto.randomBytes(24).toString("hex");
  db.prepare("DELETE FROM sess WHERE exp<?").run(Date.now());
  db.prepare("INSERT INTO sess VALUES(?,?,?)").run(tok, u.id, Date.now() + 30 * 864e5);
  res.setHeader("Set-Cookie", `sid=${tok}; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000${req.secure ? "; Secure" : ""}`);
  res.json({ user: pub(u) });
});
app.post("/api/logout", auth, (req, res) => {
  const m = /(?:^|; )sid=([^;]+)/.exec(req.headers.cookie || ""); db.prepare("DELETE FROM sess WHERE tok=?").run(m[1]);
  res.setHeader("Set-Cookie", "sid=; Path=/; Max-Age=0"); res.json({ ok: true });
});

// ---- employee ----
app.get("/api/me", auth, (req, res) => {
  const u = req.u, tod = today(), out = { user: pub(u), date: tod };
  if (u.role === "admin") return res.json(out);
  const rec = db.prepare("SELECT * FROM att WHERE user_id=? AND date=?").get(u.id, tod);
  const off = db.prepare("SELECT * FROM offs WHERE user_id=? AND date=?").get(u.id, tod);
  const open = db.prepare("SELECT * FROM att WHERE user_id=? AND out_at IS NULL ORDER BY date DESC LIMIT 1").get(u.id);
  const row = month(tod.slice(0, 7)).find(r => r.u.id === u.id);
  res.json({ ...out, rec: open || rec || null, status: stat(u, tod, rec, off, tod), month: row ? { cells: row.cells, t: row.t } : null });
});
app.post("/api/checkin", auth, (req, res) => {
  const u = req.u, tod = today();
  if (u.role !== "employee") return res.status(400).json({ error: "This account has no attendance" });
  if (db.prepare("SELECT 1 FROM att WHERE user_id=? AND out_at IS NULL").get(u.id)) return res.status(400).json({ error: "You are already on duty. Check out first." });
  if (db.prepare("SELECT 1 FROM att WHERE user_id=? AND date=?").get(u.id, tod)) return res.status(400).json({ error: "Today's attendance is already marked" });
  db.prepare("DELETE FROM offs WHERE user_id=? AND date=?").run(u.id, tod);
  db.prepare("INSERT INTO att(user_id,date,in_at) VALUES(?,?,?)").run(u.id, tod, Date.now());
  res.json({ ok: true });
});
app.post("/api/checkout", auth, (req, res) => {
  const r = db.prepare("SELECT * FROM att WHERE user_id=? AND out_at IS NULL ORDER BY date DESC LIMIT 1").get(req.u.id);
  if (!r) return res.status(400).json({ error: "You are not checked in" });
  db.prepare("UPDATE att SET out_at=? WHERE id=?").run(Date.now(), r.id); res.json({ ok: true });
});

// ---- admin ----
app.get("/api/admin/day", auth, admin, (req, res) => {
  const date = /^\d{4}-\d\d-\d\d$/.test(req.query.date || "") ? req.query.date : today(), tod = today();
  const users = db.prepare("SELECT * FROM users WHERE role='employee'").all().filter(u => !(u.left_on && u.left_on <= date) && !(u.since && u.since > date));
  res.json({ date, rows: users.map(u => {
    const rec = db.prepare("SELECT * FROM att WHERE user_id=? AND date=?").get(u.id, date), off = db.prepare("SELECT * FROM offs WHERE user_id=? AND date=?").get(u.id, date);
    const open = rec ? null : db.prepare("SELECT * FROM att WHERE user_id=? AND out_at IS NULL AND date<? ORDER BY date DESC LIMIT 1").get(u.id, date);
    return { id: u.id, empId: u.emp_id, name: u.name, section: u.section, status: stat(u, date, rec, off, tod), rec: rec || open || null, open: !!open };
  }).sort((a, b) => a.name.localeCompare(b.name)) });
});
app.post("/api/admin/mark", auth, admin, (req, res) => {
  const { userId, date, status, inTime, outTime } = req.body || {};
  const u = db.prepare("SELECT * FROM users WHERE id=? AND role='employee'").get(userId);
  if (!u || !/^\d{4}-\d\d-\d\d$/.test(date || "")) return res.status(400).json({ error: "Bad request" });
  const clear = () => { db.prepare("DELETE FROM att WHERE user_id=? AND date=?").run(u.id, date); db.prepare("DELETE FROM offs WHERE user_id=? AND date=?").run(u.id, date); };
  if (status === "rest" || status === "leave") { clear(); db.prepare("INSERT INTO offs VALUES(?,?,?)").run(u.id, date, status); }
  else if (status === "clear") clear();
  else if (status === "present") {
    const a = ms(date, inTime); let b = ms(date, outTime);
    if (!a) return res.status(400).json({ error: "In time is needed as HH:MM" });
    if (b && b < a) b += 864e5;
    clear(); db.prepare("INSERT INTO att(user_id,date,in_at,out_at) VALUES(?,?,?,?)").run(u.id, date, a, b);
  } else return res.status(400).json({ error: "Bad status" });
  res.json({ ok: true });
});
const okPin = p => /^\d{4,8}$/.test(String(p || ""));
app.get("/api/admin/users", auth, admin, (req, res) => res.json(
  db.prepare("SELECT * FROM users WHERE role='employee' AND left_on IS NULL").all().map(u => ({ id: u.id, empId: u.emp_id, name: u.name, section: u.section, rest: u.rest, since: u.since }))
    .sort((a, b) => SECTIONS.indexOf(a.section) - SECTIONS.indexOf(b.section) || a.name.localeCompare(b.name))));
app.post("/api/admin/users", auth, admin, (req, res) => {
  const { empId, name, section, rest, pin, since } = req.body || {};
  if (!/^[A-Za-z0-9._-]{2,20}$/.test(empId || "")) return res.status(400).json({ error: "Employee ID: 2 to 20 letters or numbers" });
  if (!String(name || "").trim()) return res.status(400).json({ error: "Name is needed" });
  if (!SECTIONS.includes(section)) return res.status(400).json({ error: "Pick a section" });
  if (!okPin(pin)) return res.status(400).json({ error: "PIN must be 4 to 8 digits" });
  try {
    db.prepare("INSERT INTO users(emp_id,name,pin_hash,section,rest,since) VALUES(?,?,?,?,?,?)")
      .run(empId, String(name).trim(), bcrypt.hashSync(String(pin), 10), section, rest === "" || rest == null ? null : Number(rest), /^\d{4}-\d\d-\d\d$/.test(since || "") ? since : today());
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: "That employee ID already exists" }); }
});
app.patch("/api/admin/users/:id", auth, admin, (req, res) => {
  const u = db.prepare("SELECT * FROM users WHERE id=? AND role='employee'").get(req.params.id);
  if (!u) return res.status(404).json({ error: "Not found" });
  const { rest, pin, section, name } = req.body || {};
  if (rest !== undefined) db.prepare("UPDATE users SET rest=? WHERE id=?").run(rest === "" || rest === null ? null : Number(rest), u.id);
  if (section !== undefined && SECTIONS.includes(section)) db.prepare("UPDATE users SET section=? WHERE id=?").run(section, u.id);
  if (name !== undefined && String(name).trim()) db.prepare("UPDATE users SET name=? WHERE id=?").run(String(name).trim(), u.id);
  if (pin !== undefined) { if (!okPin(pin)) return res.status(400).json({ error: "PIN must be 4 to 8 digits" }); db.prepare("UPDATE users SET pin_hash=? WHERE id=?").run(bcrypt.hashSync(String(pin), 10), u.id); db.prepare("DELETE FROM sess WHERE user_id=?").run(u.id); }
  res.json({ ok: true });
});
app.delete("/api/admin/users/:id", auth, admin, (req, res) => {
  db.prepare("UPDATE users SET left_on=? WHERE id=? AND role='employee'").run(today(), req.params.id);
  db.prepare("DELETE FROM sess WHERE user_id=?").run(req.params.id); res.json({ ok: true });
});
app.post("/api/admin/password", auth, admin, (req, res) => {
  if (!okPin(req.body && req.body.pin)) return res.status(400).json({ error: "PIN must be 4 to 8 digits" });
  db.prepare("UPDATE users SET pin_hash=? WHERE id=?").run(bcrypt.hashSync(String(req.body.pin), 10), req.u.id); res.json({ ok: true });
});
const monOk = m => /^\d{4}-(0[1-9]|1[0-2])$/.test(m || "");
app.get("/api/admin/month", auth, admin, (req, res) => {
  const mon = monOk(req.query.month) ? req.query.month : today().slice(0, 7);
  res.json({ mon, rows: month(mon).map(r => ({ name: r.u.name, empId: r.u.emp_id, section: r.u.section, ...r.t, h: +r.t.h.toFixed(1) })) });
});
app.get("/api/admin/month.csv", auth, admin, (req, res) => {
  const mon = monOk(req.query.month) ? req.query.month : today().slice(0, 7), rows = month(mon), dim = rows[0] ? rows[0].cells.length : 0;
  const q = v => `"${String(v).replace(/"/g, '""')}"`, head = ["Section", "Employee ID", "Name"];
  for (let d = 1; d <= dim; d++) head.push(d); head.push("Present", "Rest", "Leave", "Absent", "Hours");
  const lines = [head, ...rows.map(r => [r.u.section, r.u.emp_id, r.u.name, ...r.cells, r.t.P, r.t.R, r.t.L, r.t.A, r.t.h.toFixed(1)]), [], ["P = present, R = rest, L = leave, A = absent. Today and future days are left blank."]];
  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="attendance-${mon}.csv"`);
  res.send("\ufeff" + lines.map(l => l.map(q).join(",")).join("\r\n"));
});

app.listen(PORT, () => console.log(`Attendance running on port ${PORT} (time zone ${TZ})`));
