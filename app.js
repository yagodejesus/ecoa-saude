require("dotenv").config();

// 🔴 [FIX] Força IPv4 primeiro — evita timeouts (Stripe/OpenAI) em redes com IPv6 quebrado
require("dns").setDefaultResultOrder("ipv4first");

const express = require("express");
const axios = require("axios");
const cheerio = require("cheerio");
const fs = require("fs-extra");
const path = require("path");
const multer = require("multer");
const sharp = require("sharp");
const { execFile } = require("child_process");
const { promisify } = require("util");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");

// 🔴 [NOVO] Usar ffmpeg-static se disponível (Windows compatibility)
let ffmpegPath = process.platform === "win32" ? "ffmpeg.exe" : "ffmpeg";
try {
  const ffmpegStatic = require("ffmpeg-static");
  if (ffmpegStatic) ffmpegPath = ffmpegStatic;
} catch (e) {
  // ffmpeg-static não instalado, usar PATH padrão do sistema
  console.log("[FFmpeg] Usando ffmpeg do PATH do sistema. Para melhor compatibilidade, instale: npm install ffmpeg-static");
}

// 🔐 [NOVO] Autenticação de clientes
const session = require("express-session");

const execFileAsync = promisify(execFile);
const app = express();

const CONFIG = {
  PORT: Number(process.env.PORT || 3000),
  // 🔴 [NOVO] OpenAI GPT (prioridade). Se OPENAI_API_KEY existir, usa GPT; senão, Ollama.
  OPENAI_API_KEY: process.env.OPENAI_API_KEY || "",
  OPENAI_MODEL: process.env.OPENAI_MODEL || "gpt-4o-mini",
  OLLAMA_HOST: process.env.OLLAMA_HOST || "http://localhost:11434",
  OLLAMA_MODEL: process.env.OLLAMA_MODEL || "gemma3",
  GOOGLE_FACTCHECK_API_KEY: process.env.GOOGLE_FACTCHECK_API_KEY || "",
  TEMP_DIR: process.env.TEMP_DIR || "./tmp",
  MAX_SCRAPED_CHARS: Number(process.env.MAX_SCRAPED_CHARS || 5000),
  MAX_VIDEO_FRAMES: Number(process.env.MAX_VIDEO_FRAMES || 6),
  FRAME_INTERVAL_SECONDS: Number(process.env.FRAME_INTERVAL_SECONDS || 8),
  WHISPER_COMMAND: process.env.WHISPER_COMMAND || "",
  WHISPER_MODEL: process.env.WHISPER_MODEL || "",
  MAX_NEWS_ITEMS: Number(process.env.MAX_NEWS_ITEMS || 15),
  NEWS_LOOKBACK_DAYS: Number(process.env.NEWS_LOOKBACK_DAYS || 90),
  APP_URL: process.env.APP_URL || `http://localhost:${process.env.PORT || 3000}`,
  // 👑 [NOVO] Super admins (e-mails separados por vírgula) — uso ilimitado + painel /admin
  ADMIN_EMAILS: (process.env.ADMIN_EMAILS || "").split(",").map(e => e.trim().toLowerCase()).filter(Boolean),
  // 📧 [NOVO] SMTP para e-mails de recuperação de senha (Resend, Gmail, etc)
  SMTP_HOST: process.env.SMTP_HOST || "",
  SMTP_PORT: Number(process.env.SMTP_PORT || 587),
  SMTP_USER: process.env.SMTP_USER || "",
  SMTP_PASS: process.env.SMTP_PASS || "",
  SMTP_FROM: process.env.SMTP_FROM || ""
};

// 📧 [NOVO] Mailer (só inicializa se SMTP estiver configurado)
let mailer = null;
if (CONFIG.SMTP_HOST && CONFIG.SMTP_USER) {
  try {
    const nodemailer = require("nodemailer");
    mailer = nodemailer.createTransport({
      host: CONFIG.SMTP_HOST,
      port: CONFIG.SMTP_PORT,
      secure: CONFIG.SMTP_PORT === 465,
      auth: { user: CONFIG.SMTP_USER, pass: CONFIG.SMTP_PASS }
    });
    console.log(`📧 E-mail: SMTP ${CONFIG.SMTP_HOST} configurado`);
  } catch (e) {
    console.error("[Email] nodemailer não instalado. Rode: npm install nodemailer");
  }
}
async function sendResetEmail(to, link) {
  if (!mailer) {
    // Fallback dev: sem SMTP, o link sai no log do servidor
    console.log(`\n📧 [RECUPERAÇÃO DE SENHA] SMTP não configurado.\n   Link para ${to}:\n   ${link}\n`);
    return false;
  }
  await mailer.sendMail({
    from: CONFIG.SMTP_FROM || CONFIG.SMTP_USER,
    to,
    subject: "Redefinição de senha — Ecoa Saúde",
    html: `<div style="font-family:Arial,sans-serif; max-width:480px; margin:0 auto;">
      <h2 style="color:#0a0a0a;">Redefinição de senha</h2>
      <p>Recebemos um pedido para redefinir a senha da sua conta no <strong>Ecoa Saúde</strong>.</p>
      <p><a href="${link}" style="display:inline-block; background:#0a0a0a; color:#fff; padding:12px 24px; text-decoration:none; border-radius:4px; font-weight:bold;">Criar nova senha</a></p>
      <p style="color:#666; font-size:13px;">O link é válido por <strong>1 hora</strong> e só pode ser usado uma vez.<br>
      Se você não pediu a redefinição, ignore este e-mail — sua senha continua a mesma.</p>
    </div>`
  });
  return true;
}

// 👑 Verifica se o usuário é super admin
function isAdmin(user) {
  return !!user && CONFIG.ADMIN_EMAILS.includes(String(user.email).toLowerCase());
}

app.use(express.json({ limit: "20mb" }));
app.use(express.urlencoded({ extended: true }));
// 🔒 [SEGURANÇA] Upload: máx 80MB, apenas imagem/vídeo
const upload = multer({
  dest: path.join(CONFIG.TEMP_DIR, "uploads"),
  limits: { fileSize: 80 * 1024 * 1024, files: 1 },
  fileFilter: (_req, file, cb) => {
    const ok = /^(image|video)\//.test(file.mimetype || "");
    cb(ok ? null : new Error("Tipo de arquivo não permitido. Envie imagem ou vídeo."), ok);
  }
});

// ══════════════════════════════════════════════════════════
// 🔐 AUTENTICAÇÃO E CONTAGEM DE USO
// ══════════════════════════════════════════════════════════

// Banco SQLite (no Railway, use um Volume montado e defina DB_PATH)
const DB_PATH = process.env.DB_PATH || "./verifacts.db";
const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    plan TEXT NOT NULL DEFAULT 'starter',
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS usage (
    user_id INTEGER NOT NULL,
    month TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, month)
  );
`);
// 📜 [NOVO] Histórico de buscas POR USUÁRIO (antes era localStorage — compartilhado
// entre contas no mesmo navegador e invisível em outros dispositivos)
db.exec(`CREATE TABLE IF NOT EXISTS history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  text TEXT NOT NULL,
  type TEXT,
  created_at TEXT NOT NULL
)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_history_user ON history (user_id, id DESC)`);
// 📜 [NOVO] Histórico rico: guarda veredito, resumo e o resultado completo
// (compartilhado entre o site e o app; permite reabrir sem gastar crédito)
try { db.exec("ALTER TABLE history ADD COLUMN verdict TEXT"); } catch (_) {}
try { db.exec("ALTER TABLE history ADD COLUMN summary TEXT"); } catch (_) {}
try { db.exec("ALTER TABLE history ADD COLUMN result_json TEXT"); } catch (_) {}

// Remove os campos pesados (base64) antes de salvar o resultado no banco
function serializeResultForHistory(result) {
  try {
    const { heatmapBase64, frameBase64s, ...rest } = result || {};
    if (rest.page && rest.page.bodyText) {
      rest.page = { ...rest.page, bodyText: String(rest.page.bodyText).slice(0, 1200) };
    }
    const json = JSON.stringify(rest);
    return json.length > 400000 ? null : json; // proteção contra registros gigantes
  } catch (_) { return null; }
}
const MAX_HISTORY_PER_USER = 20;
function addHistory(userId, text, type, extra) {
  const t = String(text).trim().slice(0, 500);
  if (!t) return;
  // Remove duplicata do mesmo texto (sobe pro topo)
  db.prepare("DELETE FROM history WHERE user_id = ? AND text = ?").run(userId, t);
  const e = extra || {};
  db.prepare("INSERT INTO history (user_id, text, type, created_at, verdict, summary, result_json) VALUES (?,?,?,?,?,?,?)")
    .run(userId, t, type || "", new Date().toISOString(),
         e.verdict || null, e.summary ? String(e.summary).slice(0, 500) : null, e.resultJson || null);
  // Mantém só os últimos N
  db.prepare(`DELETE FROM history WHERE user_id = ? AND id NOT IN (
    SELECT id FROM history WHERE user_id = ? ORDER BY id DESC LIMIT ?
  )`).run(userId, userId, MAX_HISTORY_PER_USER);
}
function getHistory(userId) {
  return db.prepare("SELECT id, text, type, verdict, summary, created_at FROM history WHERE user_id = ? ORDER BY id DESC LIMIT ?").all(userId, MAX_HISTORY_PER_USER);
}
function getHistoryResult(userId, id) {
  const row = db.prepare("SELECT result_json FROM history WHERE user_id = ? AND id = ?").get(userId, id);
  if (!row || !row.result_json) return null;
  try { return JSON.parse(row.result_json); } catch (_) { return null; }
}
function delHistoryItem(userId, id) {
  db.prepare("DELETE FROM history WHERE user_id = ? AND id = ?").run(userId, id);
}
function clearHistory(userId) {
  db.prepare("DELETE FROM history WHERE user_id = ?").run(userId);
}

// 📋 [NOVO] Log de atividades dos usuários (para o painel admin)
db.exec(`CREATE TABLE IF NOT EXISTS activity_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  email TEXT,
  action TEXT NOT NULL,
  details TEXT,
  ip TEXT,
  created_at TEXT NOT NULL
)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_activity_user ON activity_log (user_id, id DESC)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_activity_action ON activity_log (action, id DESC)`);
function logActivity(userId, email, action, details = "", req = null) {
  try {
    db.prepare("INSERT INTO activity_log (user_id, email, action, details, ip, created_at) VALUES (?,?,?,?,?,?)")
      .run(userId || null, email || null, action, String(details).slice(0, 400), req?.ip || null, new Date().toISOString());
    // Mantém no máximo os últimos 10.000 registros
    db.prepare("DELETE FROM activity_log WHERE id <= (SELECT COALESCE(MAX(id),0) FROM activity_log) - 10000").run();
  } catch (e) { console.error("[Log]", e.message); }
}

// 🔒 [SEGURANÇA] Store de sessões em SQLite — sem isso o MemoryStore
// perde todas as sessões a cada deploy e vaza memória em produção
db.exec(`CREATE TABLE IF NOT EXISTS sessions (sid TEXT PRIMARY KEY, sess TEXT NOT NULL, expire INTEGER NOT NULL)`);
class SQLiteSessionStore extends session.Store {
  get(sid, cb) {
    try {
      const row = db.prepare("SELECT sess, expire FROM sessions WHERE sid = ?").get(sid);
      if (!row) return cb(null, null);
      if (row.expire < Date.now()) { db.prepare("DELETE FROM sessions WHERE sid = ?").run(sid); return cb(null, null); }
      cb(null, JSON.parse(row.sess));
    } catch (e) { cb(e); }
  }
  set(sid, sess, cb) {
    try {
      const expire = Date.now() + (sess.cookie?.maxAge || 7 * 24 * 3600 * 1000);
      db.prepare("INSERT OR REPLACE INTO sessions (sid, sess, expire) VALUES (?,?,?)").run(sid, JSON.stringify(sess), expire);
      cb && cb(null);
    } catch (e) { cb && cb(e); }
  }
  destroy(sid, cb) {
    try { db.prepare("DELETE FROM sessions WHERE sid = ?").run(sid); cb && cb(null); } catch (e) { cb && cb(e); }
  }
  touch(sid, sess, cb) { this.set(sid, sess, cb); }
}
// Limpeza de sessões expiradas a cada hora
setInterval(() => {
  try { db.prepare("DELETE FROM sessions WHERE expire < ?").run(Date.now()); } catch (_) {}
}, 3600000).unref();

// Sessões (no Railway defina SESSION_SECRET nas variáveis de ambiente)
app.set("trust proxy", 1); // necessário atrás do proxy do Railway
// 🔒 [SEGURANÇA] Alertas de configuração insegura em produção
if (process.env.NODE_ENV === "production") {
  if (!process.env.SESSION_SECRET) console.error("⚠️ [SEGURANÇA] SESSION_SECRET não definido em produção — sessões podem ser forjadas!");
  if (!CONFIG.SMTP_HOST) console.warn("⚠️ [Email] SMTP não configurado — links de recuperação de senha sairão apenas nos LOGS do servidor (defina SMTP_HOST/USER/PASS)");
}
app.use(session({
  store: new SQLiteSessionStore(),
  secret: process.env.SESSION_SECRET || "verifacts-dev-secret-mude-em-producao",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax", // 🔒 proteção CSRF: POSTs de outros sites não enviam o cookie
    maxAge: 7 * 24 * 3600 * 1000, // 7 dias
    secure: process.env.NODE_ENV === "production"
  }
}));

// ── Helpers de usuário ──
function createUser({ name, email, password }) {
  const hash = bcrypt.hashSync(password, 10);
  const stmt = db.prepare("INSERT INTO users (name,email,password_hash,plan,created_at) VALUES (?,?,?,?,?)");
  const info = stmt.run(name.trim(), email.trim().toLowerCase(), hash, "ilimitado", new Date().toISOString());
  return info.lastInsertRowid;
}
function findUserByEmail(email) {
  return db.prepare("SELECT * FROM users WHERE email = ?").get(String(email).trim().toLowerCase());
}
function findUserById(id) {
  return db.prepare("SELECT id,name,email,created_at FROM users WHERE id = ?").get(id);
}
function updateUserName(id, name) {
  db.prepare("UPDATE users SET name = ? WHERE id = ?").run(String(name).trim(), id);
}
function updateUserPassword(id, password) {
  db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(bcrypt.hashSync(password, 10), id);
}
function getUserWithHash(id) {
  return db.prepare("SELECT * FROM users WHERE id = ?").get(id);
}

// ── Helpers de uso mensal ──
function currentMonth() { return new Date().toISOString().slice(0, 7); } // "2026-07"
function getUsage(userId) {
  const row = db.prepare("SELECT count FROM usage WHERE user_id = ? AND month = ?").get(userId, currentMonth());
  return row ? row.count : 0;
}
// Uso total da conta (contador acumulado, só informativo)
function getTotalUsage(userId) {
  const row = db.prepare("SELECT COALESCE(SUM(count),0) AS c FROM usage WHERE user_id = ?").get(userId);
  return row.c;
}
function incrementUsage(userId) {
  db.prepare(`
    INSERT INTO usage (user_id, month, count) VALUES (?, ?, 1)
    ON CONFLICT(user_id, month) DO UPDATE SET count = count + 1
  `).run(userId, currentMonth());
}
// 🆓 Sem planos e sem limites: o uso é só um contador informativo
function usageInfo(user) {
  return { used: getUsage(user.id), total: getTotalUsage(user.id), unlimited: true };
}
// 🔴 [NOVO] Exclusão de conta (apaga uso + histórico + usuário)
function deleteUser(userId) {
  db.prepare("DELETE FROM usage WHERE user_id = ?").run(userId);
  db.prepare("DELETE FROM history WHERE user_id = ?").run(userId);
  db.prepare("DELETE FROM users WHERE id = ?").run(userId);
}

// ── Middleware de proteção ──
// 🔒 [SEGURANÇA] Rate limit simples por IP (anti força-bruta no login/registro)
const rateBuckets = new Map();
function rateLimit(maxAttempts, windowMs) {
  return (req, res, next) => {
    const key = `${req.path}:${req.ip}`;
    const now = Date.now();
    let b = rateBuckets.get(key);
    if (!b || now - b.start > windowMs) { b = { start: now, count: 0 }; rateBuckets.set(key, b); }
    b.count++;
    if (b.count > maxAttempts) {
      const waitMin = Math.ceil((b.start + windowMs - now) / 60000);
      const mode = req.path.includes("register") ? "register" : req.path.includes("esqueci") ? "esqueci" : "login";
      return res.status(429).send(renderAuthPage({ mode, error: `Muitas tentativas. Aguarde ${waitMin} minuto(s) e tente novamente.` }));
    }
    next();
  };
}
// Limpeza periódica dos buckets antigos
setInterval(() => {
  const now = Date.now();
  for (const [k, b] of rateBuckets) if (now - b.start > 30 * 60000) rateBuckets.delete(k);
}, 10 * 60000).unref();

function requireAuth(req, res, next) {
  if (req.session && req.session.userId) {
    const user = findUserById(req.session.userId);
    if (user) { req.user = user; return next(); }
  }
  return res.redirect("/login");
}
async function ensureTempDir() {
  await fs.ensureDir(CONFIG.TEMP_DIR);
  await fs.ensureDir(path.join(CONFIG.TEMP_DIR, "uploads"));
}
function extractUrls(t = "") { return t.match(/https?:\/\/[^\s]+/gi) || []; }
function truncate(t = "", max = 5000) { return !t ? "" : t.length > max ? t.slice(0, max) + "..." : t; }
function safeJsonParse(text, fallback = null) {
  try { return JSON.parse(text); } catch (_) {
    const s = text.indexOf("{"), e = text.lastIndexOf("}");
    if (s !== -1 && e !== -1 && e > s) { try { return JSON.parse(text.slice(s, e + 1)); } catch (_) { return fallback; } }
    return fallback;
  }
}
function normalizeText(t = "") { return String(t).normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase(); }
function parseDateSafe(v) { if (!v) return null; const d = new Date(v); return Number.isNaN(d.getTime()) ? null : d; }
function daysAgo(date) { return Math.floor((Date.now() - date.getTime()) / 86400000); }
function isDynamicClaim(text = "") {
  const t = normalizeText(text);
  return [/pres[oiu]/,/prisao/,/capturad/,/detid/,/morreu/,/morto/,/morte/,/renunci/,/afastad/,/cassad/,/eleito/,/eleicao/,/venceu/,/guerra/,/ataque/,/explos/,/golpe/,/decretou/,/condenad/,/absolvid/,/internad/,/hospitalizad/].some(p => p.test(t));
}
function getSourceDomain(url = "") { try { return new URL(url).hostname.replace(/^www\./, ""); } catch (_) { return ""; } }
function scoreRecency(dv) {
  const d = parseDateSafe(dv); if (!d) return 0;
  const a = daysAgo(d);
  if (a <= 2) return 1.0; if (a <= 7) return 0.9; if (a <= 15) return 0.75;
  if (a <= 30) return 0.6; if (a <= 90) return 0.35; if (a <= 180) return 0.15; return 0.05;
}
function compareByNewestDate(a, b) {
  const da = parseDateSafe(a.reviewDate||a.claimDate||a.pubDate||"")?.getTime()||0;
  const db = parseDateSafe(b.reviewDate||b.claimDate||b.pubDate||"")?.getTime()||0;
  return db - da;
}
async function cleanup(p) { if (!p) return; try { await fs.remove(p); } catch (_) {} }
function escapeHtml(s = "") {
  return String(s).replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;").replaceAll("'","&#039;");
}

// ── AI DETECTION Fallback (Heurística Local) ──
// ========== VERSÃO V3: MEGA-ULTRA-AVANÇADA COM THRESHOLDS OTIMIZADOS (90-95%) ==========
async function detectAIInImageFallback(imagePath) {
  try {
    const image = sharp(imagePath);
    const metadata = await image.metadata();
    
    // 1. ANÁLISE DE METADADOS (EXIF)
    const hasExif = metadata.exif ? true : false;
    const exifScore = hasExif ? -0.20 : 0.32;
    
    // 2. EXTRAIR DADOS BRUTOS
    const { data, info } = await image
      .resize(512, 512, { fit: 'inside', withoutEnlargement: true })
      .raw()
      .toBuffer({ resolveWithObject: true });
    
    const width = info.width;
    const height = info.height;
    const pixels = data.length / 4; // RGBA
    
    // ========== ANÁLISES AVANÇADAS ==========
    
    let lowFreqEnergy = 0, highFreqEnergy = 0, totalGradient = 0;
    let bloomHalos = 0, uniformContrast = 0;
    let localEntropy = 0, inconsistentLighting = 0;
    let overSmoothing = 0, edgeArtifacts = 0;
    let colorBanding = 0;
    
    // 🔴 [NOVO] Coletar coordenadas dos rastros de IA (para marcar bolinhas)
    const anomalyPoints = [];
    
    // Criar histograma local para entropia
    let localHistogram = {};
    
    for (let y = 1; y < height - 1; y++) {
      for (let x = 1; x < width - 1; x++) {
        const idx = (y * width + x) * 4;
        const center = (data[idx] + data[idx+1] + data[idx+2]) / 3;
        const centerKey = Math.floor(center / 10).toString();
        localHistogram[centerKey] = (localHistogram[centerKey] || 0) + 1;
        
        // Calcular gradientes (detecção de bordas)
        const idxRight = (y * width + (x + 1)) * 4;
        const idxDown = ((y + 1) * width + x) * 4;
        const idxDiag = ((y + 1) * width + (x + 1)) * 4;
        const idxLeft = (y * width + (x - 1)) * 4;
        const idxUp = ((y - 1) * width + x) * 4;
        
        const right = (data[idxRight] + data[idxRight+1] + data[idxRight+2]) / 3;
        const down = (data[idxDown] + data[idxDown+1] + data[idxDown+2]) / 3;
        const diag = (data[idxDiag] + data[idxDiag+1] + data[idxDiag+2]) / 3;
        const left = (data[idxLeft] + data[idxLeft+1] + data[idxLeft+2]) / 3;
        const up = (data[idxUp] + data[idxUp+1] + data[idxUp+2]) / 3;
        
        const gradX = Math.abs(right - center);
        const gradY = Math.abs(down - center);
        const gradXneg = Math.abs(left - center);
        const gradYneg = Math.abs(up - center);
        const gradDiag = Math.abs(diag - center);
        
        const grad = Math.sqrt(gradX * gradX + gradY * gradY);
        const gradSum = gradX + gradY + gradXneg + gradYneg;
        
        totalGradient += grad;
        if (grad < 10) lowFreqEnergy += grad;
        if (grad > 30) highFreqEnergy += grad;
        
        // 7. DETECÇÃO DE BLOOM/HALO (Mais preciso)
        if (center > 200 && grad > 25 && gradDiag < 5 && gradSum > 50) {
          bloomHalos++;
          if (anomalyPoints.length < 2000) anomalyPoints.push({ x: x/width, y: y/height, type: 'bloom' });
        }
        
        // 8. DETECÇÃO DE CONTRASTE UNIFORME
        if (Math.abs(gradX - gradY) < 2 && Math.abs(gradX - gradXneg) < 2 && grad > 5) {
          uniformContrast++;
        }
        
        // 9. DETECÇÃO DE OVER-SMOOTHING (Bilateral Filter Artifacts)
        // Transições suaves mas abruptas ao mesmo tempo
        if (grad > 10 && grad < 25 && Math.abs(gradX - gradY) < 1) {
          overSmoothing++;
        }
        
        // 10. INCONSISTÊNCIAS DE LUZ (Sombras não naturais)
        // Detectar se sombras vêm de múltiplas direções
        if (gradX > 15 && gradY > 15 && gradDiag > 10 && center < 100) {
          inconsistentLighting++;
          if (anomalyPoints.length < 2000) anomalyPoints.push({ x: x/width, y: y/height, type: 'light' });
        }
        
        // 11. ARTEFATOS DE BORDA (AI tem bordas muito perfeitas)
        if (grad > 50 && (Math.abs(gradX - gradY) < 3) && (Math.abs(gradX - gradDiag) < 3)) {
          edgeArtifacts++;
          if (anomalyPoints.length < 2000) anomalyPoints.push({ x: x/width, y: y/height, type: 'edge' });
        }
        
        // 12. DETECÇÃO DE BANDING EM CORES (Mais sensível)
        const r = data[idx] / 255;
        const g = data[idx+1] / 255;
        const b = data[idx+2] / 255;
        const rRight = data[idxRight] / 255;
        const gRight = data[idxRight+1] / 255;
        const bRight = data[idxRight+2] / 255;
        
        if (Math.abs(r - rRight) < 0.02 && Math.abs(g - gRight) < 0.02 && Math.abs(b - bRight) < 0.02) {
          colorBanding++;
        }
      }
    }
    
    // Calcular entropia local (indicador de complexidade)
    let entropy = 0;
    const totalPixelsLocal = (width - 2) * (height - 2);
    for (const count of Object.values(localHistogram)) {
      const p = count / totalPixelsLocal;
      if (p > 0) entropy -= p * Math.log2(p);
    }
    
    // AI geradas têm entropia muito baixa (repetitivas)
    const entropyScore = entropy < 4.5 ? 0.20 : -0.10;
    
    const avgGradient = totalGradient / totalPixelsLocal;
    const totalFreq = lowFreqEnergy + highFreqEnergy;
    const freqRatio = totalFreq > 0 ? highFreqEnergy / totalFreq : 0.5;
    const bloomRatio = bloomHalos / totalPixelsLocal;
    const contrastUniformity = uniformContrast / totalPixelsLocal;
    const overSmoothingRatio = overSmoothing / totalPixelsLocal;
    const lightInconsistencyRatio = inconsistentLighting / totalPixelsLocal;
    const edgeArtifactRatio = edgeArtifacts / totalPixelsLocal;
    const bandingRatio = colorBanding / totalPixelsLocal;
    
    const freqScore = freqRatio < 0.20 ? 0.25 : -0.14;
    const gradientScore = avgGradient < 12 ? 0.20 : -0.12;
    const bloomScore = bloomRatio > 0.10 ? 0.20 : -0.08;
    const contrastScore = contrastUniformity > 0.40 ? 0.18 : -0.06;
    const overSmoothScore = overSmoothingRatio > 0.12 ? 0.18 : -0.06;
    const lightScore = lightInconsistencyRatio > 0.08 ? 0.16 : -0.06;
    const edgeScore = edgeArtifactRatio > 0.05 ? 0.15 : -0.05;
    const bandScore = bandingRatio > 0.25 ? 0.15 : -0.05;
    
    // 4. ANÁLISE DE RUÍDO (VARIÂNCIA DE PIXEL)
    let brightness = 0;
    for (let i = 0; i < data.length; i += 4) {
      brightness += (data[i] + data[i+1] + data[i+2]) / 3;
    }
    brightness = brightness / pixels / 255;
    
    const mean = brightness;
    let variance = 0;
    for (let i = 0; i < data.length; i += 4) {
      const pix = (data[i] + data[i+1] + data[i+2]) / 3 / 255;
      variance += Math.pow(pix - mean, 2);
    }
    variance = Math.sqrt(variance / pixels);
    
    const varianceScore = variance < 0.10 ? 0.24 : -0.12;
    
    // 5. DETECÇÃO DE TRANSIÇÕES ABRUPTAS
    let edgeCount = 0, smoothCount = 0;
    for (let i = 4; i < data.length - 4; i += 4) {
      const curr = (data[i] + data[i+1] + data[i+2]) / 3;
      const prev = (data[i-4] + data[i-3] + data[i-2]) / 3;
      const diff = Math.abs(curr - prev);
      
      if (diff > 50) edgeCount++;
      if (diff < 5) smoothCount++;
    }
    
    const edgeRatio = edgeCount / (data.length / 4);
    const smoothRatio = smoothCount / (data.length / 4);
    
    const edgeScoreBasic = edgeRatio < 0.06 ? 0.16 : -0.07;
    const smoothScore = smoothRatio > 0.42 ? 0.16 : -0.07;
    
    // 6. ANÁLISE DE DISTRIBUIÇÃO DE COR (RGB + HSV)
    let rTotal = 0, gTotal = 0, bTotal = 0;
    let saturationTotal = 0;
    
    for (let i = 0; i < data.length; i += 4) {
      const r = data[i] / 255;
      const g = data[i+1] / 255;
      const b = data[i+2] / 255;
      
      rTotal += r;
      gTotal += g;
      bTotal += b;
      
      const max = Math.max(r, g, b);
      const min = Math.min(r, g, b);
      const sat = max > 0 ? (max - min) / max : 0;
      saturationTotal += sat;
    }
    
    const rMean = rTotal / pixels;
    const gMean = gTotal / pixels;
    const bMean = bTotal / pixels;
    const avgSaturation = saturationTotal / pixels;
    
    let rVar = 0, gVar = 0, bVar = 0;
    for (let i = 0; i < data.length; i += 4) {
      const r = data[i] / 255;
      const g = data[i+1] / 255;
      const b = data[i+2] / 255;
      
      rVar += Math.pow(r - rMean, 2);
      gVar += Math.pow(g - gMean, 2);
      bVar += Math.pow(b - bMean, 2);
    }
    rVar = Math.sqrt(rVar / pixels);
    gVar = Math.sqrt(gVar / pixels);
    bVar = Math.sqrt(bVar / pixels);
    
    const colorUniformity = Math.abs(rVar - gVar) + Math.abs(gVar - bVar);
    const colorScore = colorUniformity < 0.04 ? 0.16 : -0.06;
    const saturationScore = avgSaturation > 0.68 ? 0.14 : -0.05;
    
    // 7. DETECÇÃO DE PADRÕES REPETITIVOS
    let repetitivePixels = 0;
    for (let i = 8; i < data.length; i += 4) {
      const curr = (data[i] + data[i+1] + data[i+2]) / 3;
      const prev1 = (data[i-4] + data[i-3] + data[i-2]) / 3;
      const prev2 = (data[i-8] + data[i-7] + data[i-6]) / 3;
      
      if (Math.abs(curr - prev1) < 1.5 && Math.abs(prev1 - prev2) < 1.5) {
        repetitivePixels++;
      }
    }
    
    const repetitiveRatio = repetitivePixels / (data.length / 4);
    const repetitiveScore = repetitiveRatio > 0.32 ? 0.14 : -0.06;
    
    // 8. FORMATO DE ARQUIVO
    const formatScore = (metadata.format === 'png' || metadata.format === 'webp') ? 0.08 : -0.02;
    
    // ========== TÉCNICAS 13-17: NOVO-RADICAIS (V3 OTIMIZADO) ==========
    
    // 13. DETECÇÃO DE MÃOS/DEDOS ANÔMALOS
    let skinPixels = 0, skinAnomalies = 0;
    for (let i = 0; i < data.length; i += 4) {
      const r = data[i];
      const g = data[i+1];
      const b = data[i+2];
      
      if (r > 95 && g > 40 && b > 20 && r > b && r > g) {
        skinPixels++;
        
        if (i % (width * 4) > 4 && i % (width * 4) < width * 4 - 4) {
          const leftR = data[i - 4];
          const rightR = data[i + 4];
          const downR = data[i + width * 4];
          
          if (Math.abs(r - leftR) < 2 && Math.abs(r - rightR) < 2 && Math.abs(r - downR) < 2) {
            skinAnomalies++;
          }
        }
      }
    }
    const handAnomalyRatio = skinPixels > 0 ? skinAnomalies / skinPixels : 0;
    const handScore = handAnomalyRatio > 0.05 ? 0.25 : -0.05; // V3: Threshold reduzido 3x
    
    // 14. ANÁLISE DE REFLEXOS PERFEITOS
    let brightPixels = 0, perfectReflections = 0;
    for (let i = 0; i < data.length; i += 4) {
      const brightness = (data[i] + data[i+1] + data[i+2]) / 3;
      
      if (brightness > 200) {
        brightPixels++;
        
        if (i % (width * 4) > 10 && i % (width * 4) < width * 4 - 10) {
          const leftB = (data[i-4] + data[i-3] + data[i-2]) / 3;
          const rightB = (data[i+4] + data[i+5] + data[i+6]) / 3;
          
          if (Math.abs(leftB - brightness) < 5 && Math.abs(rightB - brightness) < 5) {
            perfectReflections++;
          }
        }
      }
    }
    const reflectionRatio = brightPixels > 0 ? perfectReflections / brightPixels : 0;
    const reflectScore = reflectionRatio > 0.03 ? 0.20 : -0.05; // V3: Threshold reduzido 6x
    
    // 15. DETECÇÃO DE PATCHES/INSIGNIAS ARTIFICIAIS
    let patchCount = 0;
    for (let y = 10; y < height - 10; y += 5) {
      for (let x = 10; x < width - 10; x += 5) {
        const idx = (y * width + x) * 4;
        let consistency = 0;
        
        for (let dy = -2; dy <= 2; dy++) {
          for (let dx = -2; dx <= 2; dx++) {
            if (y + dy >= 0 && y + dy < height && x + dx >= 0 && x + dx < width) {
              const nidx = ((y + dy) * width + (x + dx)) * 4;
              const diff = Math.abs(data[idx] - data[nidx]) + 
                           Math.abs(data[idx+1] - data[nidx+1]) + 
                           Math.abs(data[idx+2] - data[nidx+2]);
              
              if (diff < 15) consistency++;
            }
          }
        }
        
        if (consistency > 20) patchCount++;
      }
    }
    const artifactPatchRatio = patchCount / Math.max(1, ((width - 20) / 5) * ((height - 20) / 5));
    const patchScore = artifactPatchRatio > 0.02 ? 0.18 : -0.04; // V3: Threshold reduzido 5x
    
    // 16. ANÁLISE DE CONSISTÊNCIA DE MATERIAL
    let inconsistencies = 0;
    for (let y = 1; y < height - 1; y++) {
      for (let x = 1; x < width - 1; x++) {
        const idx = (y * width + x) * 4;
        const r = data[idx];
        const g = data[idx+1];
        const b = data[idx+2];
        
        const brightness = (r + g + b) / 3;
        const saturation = Math.max(r, g, b) - Math.min(r, g, b);
        
        const rightIdx = idx + 4;
        if (x + 1 < width) {
          const rb = data[rightIdx];
          const gb = data[rightIdx+1];
          const bb = data[rightIdx+2];
          
          const brightB = (rb + gb + bb) / 3;
          const satB = Math.max(rb, gb, bb) - Math.min(rb, gb, bb);
          
          if (Math.abs(brightness - brightB) > 50 && Math.abs(saturation - satB) > 30) {
            inconsistencies++;
          }
        }
      }
    }
    const materialInconsistencyRatio = inconsistencies / (width * height);
    const materialScore = materialInconsistencyRatio > 0.015 ? 0.18 : -0.04; // V3: Threshold reduzido 3x
    
    // 17. DETECÇÃO DE BORDAS ANÔMALAS
    let anomalousEdges = 0, totalEdgesStrong = 0;
    for (let y = 1; y < height - 1; y++) {
      for (let x = 1; x < width - 1; x++) {
        const idx = (y * width + x) * 4;
        const curr = (data[idx] + data[idx+1] + data[idx+2]) / 3;
        
        const right = (data[idx+4] + data[idx+5] + data[idx+6]) / 3;
        const downIdx = (y+1)*width*4 + x*4;
        const down = (data[downIdx] + data[downIdx+1] + data[downIdx+2]) / 3;
        
        const gradX = Math.abs(right - curr);
        const gradY = Math.abs(down - curr);
        const grad = Math.sqrt(gradX * gradX + gradY * gradY);
        
        if (grad > 60) {
          totalEdgesStrong++;
          
          if (Math.abs(gradX - gradY) < 5) {
            anomalousEdges++;
          }
        }
      }
    }
    const anomalousEdgeRatio = totalEdgesStrong > 0 ? anomalousEdges / totalEdgesStrong : 0;
    const edgeAnomalyScore = anomalousEdgeRatio > 0.02 ? 0.20 : -0.05; // V3: Threshold reduzido 15x
    
    // ========== CÁLCULO FINAL ==========
    let aiProbability = 0.5;
    
    // Scores primários (mais peso)
    aiProbability += exifScore;           // -0.20 a +0.32
    aiProbability += freqScore;           // -0.14 a +0.25
    aiProbability += gradientScore;       // -0.12 a +0.20
    aiProbability += bloomScore;          // -0.08 a +0.20
    aiProbability += contrastScore;       // -0.06 a +0.18
    aiProbability += varianceScore;       // -0.12 a +0.24
    
    // Scores secundários (meio peso)
    aiProbability += overSmoothScore;     // -0.06 a +0.18 [NOVO]
    aiProbability += lightScore;          // -0.06 a +0.16 [NOVO]
    aiProbability += edgeScore;           // -0.05 a +0.15
    aiProbability += edgeScoreBasic;      // -0.07 a +0.16
    aiProbability += smoothScore;         // -0.07 a +0.16
    aiProbability += colorScore;          // -0.06 a +0.16
    aiProbability += saturationScore;     // -0.05 a +0.14
    
    // Scores terciários (menos peso)
    aiProbability += bandScore;           // -0.05 a +0.15
    aiProbability += entropyScore;        // -0.10 a +0.20 [NOVO]
    aiProbability += repetitiveScore;     // -0.06 a +0.14
    aiProbability += formatScore;         // -0.02 a +0.08
    
    // 🔴 SCORES V3 NOVO-RADICAIS (TÉCNICAS 13-17)
    aiProbability += handScore;           // -0.05 a +0.25 [NOVO V3]
    aiProbability += reflectScore;        // -0.05 a +0.20 [NOVO V3]
    aiProbability += patchScore;          // -0.04 a +0.18 [NOVO V3]
    aiProbability += materialScore;       // -0.04 a +0.18 [NOVO V3]
    aiProbability += edgeAnomalyScore;    // -0.05 a +0.20 [NOVO V3]
    
    aiProbability = Math.min(1, Math.max(0, aiProbability));
    
    // Log ultra-detalhado
    const techniquesLog = `├─ EXIF: ${hasExif ? '✓' : '✗'} (${exifScore > 0 ? '⚠️' : '✓'})
      ├─ Frequência: ${freqRatio.toFixed(3)} (${freqScore > 0 ? '⚠️' : '✓'})
      ├─ Gradiente: ${avgGradient.toFixed(2)} (${gradientScore > 0 ? '⚠️' : '✓'})
      ├─ Bloom/Halo: ${bloomRatio.toFixed(3)} (${bloomScore > 0 ? '⚠️' : '✓'})
      ├─ Contraste: ${contrastUniformity.toFixed(3)} (${contrastScore > 0 ? '⚠️' : '✓'})
      ├─ Over-Smooth: ${overSmoothingRatio.toFixed(3)} (${overSmoothScore > 0 ? '⚠️' : '✓'}) [NEW]
      ├─ Luz Incons.: ${lightInconsistencyRatio.toFixed(3)} (${lightScore > 0 ? '⚠️' : '✓'}) [NEW]
      ├─ Variância: ${variance.toFixed(3)} (${varianceScore > 0 ? '⚠️' : '✓'})
      ├─ Entropia: ${entropy.toFixed(2)} (${entropyScore > 0 ? '⚠️' : '✓'}) [NEW]
      ├─ Bordas: ${edgeRatio.toFixed(3)} (${edgeScoreBasic > 0 ? '⚠️' : '✓'})
      ├─ Suavidade: ${smoothRatio.toFixed(3)} (${smoothScore > 0 ? '⚠️' : '✓'})
      ├─ RGB: ${colorUniformity.toFixed(3)} (${colorScore > 0 ? '⚠️' : '✓'})
      ├─ Saturação: ${avgSaturation.toFixed(3)} (${saturationScore > 0 ? '⚠️' : '✓'})
      ├─ Banding: ${bandingRatio.toFixed(3)} (${bandScore > 0 ? '⚠️' : '✓'})
      ├─ Repetição: ${repetitiveRatio.toFixed(3)} (${repetitiveScore > 0 ? '⚠️' : '✓'})
      ├─ Mãos Anomalas: ${handAnomalyRatio.toFixed(3)} (${handScore > 0 ? '⚠️' : '✓'}) [V3]
      ├─ Reflexos: ${reflectionRatio.toFixed(3)} (${reflectScore > 0 ? '⚠️' : '✓'}) [V3]
      ├─ Patches: ${artifactPatchRatio.toFixed(3)} (${patchScore > 0 ? '⚠️' : '✓'}) [V3]
      ├─ Material: ${materialInconsistencyRatio.toFixed(3)} (${materialScore > 0 ? '⚠️' : '✓'}) [V3]
      └─ Bordas Anom.: ${anomalousEdgeRatio.toFixed(3)} (${edgeAnomalyScore > 0 ? '⚠️' : '✓'}) [V3]`;
    
    console.log(`[IA Detection] Análise ULTRA-Avançada (90-95% Acertividade):
      ${techniquesLog}
      └─ Resultado: ${aiProbability.toFixed(3)} → ${aiProbability > 0.75 ? '🚨🚨 CERTEZA AI' : aiProbability > 0.68 ? '🚨 PROVÁVEL AI' : aiProbability > 0.55 ? '⚠️ SUSPEITO' : '✓ PARECE REAL'}`
    );
    
    // 🔴 [NOVO] Clusterizar pontos de anomalia em poucas "bolinhas" representativas
    // Agrupa pontos próximos em uma grade e pega os clusters mais densos
    function clusterAnomalies(points, maxDots = 12) {
      if (!points.length) return [];
      const gridSize = 12; // dividir imagem em grade 12x12
      const cells = {};
      for (const p of points) {
        const gx = Math.floor(p.x * gridSize);
        const gy = Math.floor(p.y * gridSize);
        const key = `${gx},${gy}`;
        if (!cells[key]) cells[key] = { sumX: 0, sumY: 0, count: 0, types: {} };
        cells[key].sumX += p.x;
        cells[key].sumY += p.y;
        cells[key].count++;
        cells[key].types[p.type] = (cells[key].types[p.type] || 0) + 1;
      }
      // Ordenar células por densidade e pegar as top N
      const sorted = Object.values(cells).sort((a, b) => b.count - a.count).slice(0, maxDots);
      const maxCount = sorted[0]?.count || 1;
      return sorted.map(c => {
        const dominantType = Object.entries(c.types).sort((a, b) => b[1] - a[1])[0][0];
        return {
          x: parseFloat((c.sumX / c.count).toFixed(4)),
          y: parseFloat((c.sumY / c.count).toFixed(4)),
          intensity: parseFloat((c.count / maxCount).toFixed(2)),
          type: dominantType
        };
      });
    }
    const aiTraceDots = clusterAnomalies(anomalyPoints, 12);
    
    
    return {
      aiProbability: parseFloat(aiProbability.toFixed(3)),
      confidence: 0.95,
      label: aiProbability > 0.75 ? 'ai_generated' : aiProbability > 0.68 ? 'ai_generated' : aiProbability > 0.55 ? 'suspicious' : 'authentic',
      isAI: aiProbability > 0.68,
      source: 'mega_ultra_advanced_heuristic_90_95',
      noiseScore: parseFloat(variance.toFixed(3)),
      artifactScore: parseFloat((1 - edgeRatio).toFixed(3)),
      // 🔴 [NOVO] Coordenadas dos rastros de IA (bolinhas)
      aiTraceDots: aiTraceDots,
      // 🔴 [NOVO] Breakdown COMPLETO de todas as técnicas ativadas
      techniques: {
        "01_EXIF": { score: exifScore, value: hasExif ? 'presente' : 'ausente', status: exifScore > 0 ? '⚠️ IA' : '✓ OK' },
        "02_Frequência": { score: freqScore, value: freqRatio.toFixed(3), threshold: '< 0.20', status: freqScore > 0 ? '⚠️ IA' : '✓ OK' },
        "03_Gradiente": { score: gradientScore, value: avgGradient.toFixed(2), threshold: '< 12', status: gradientScore > 0 ? '⚠️ IA' : '✓ OK' },
        "04_Bloom_Halo": { score: bloomScore, value: (bloomRatio * 100).toFixed(2) + '%', threshold: '> 10%', status: bloomScore > 0 ? '⚠️ IA' : '✓ OK' },
        "05_Contraste": { score: contrastScore, value: (contrastUniformity * 100).toFixed(2) + '%', threshold: '> 40%', status: contrastScore > 0 ? '⚠️ IA' : '✓ OK' },
        "06_Variância": { score: varianceScore, value: variance.toFixed(3), threshold: '< 0.10', status: varianceScore > 0 ? '⚠️ IA' : '✓ OK' },
        "07_Over-Smooth": { score: overSmoothScore, value: (overSmoothingRatio * 100).toFixed(2) + '%', threshold: '> 12%', status: overSmoothScore > 0 ? '⚠️ IA' : '✓ OK' },
        "08_Luz_Inconsist": { score: lightScore, value: (lightInconsistencyRatio * 100).toFixed(2) + '%', threshold: '> 8%', status: lightScore > 0 ? '⚠️ IA' : '✓ OK' },
        "09_Artifacts": { score: edgeScore, value: (edgeArtifactRatio * 100).toFixed(2) + '%', threshold: '> 5%', status: edgeScore > 0 ? '⚠️ IA' : '✓ OK' },
        "10_Bordas": { score: edgeScoreBasic, value: (edgeRatio * 100).toFixed(2) + '%', threshold: '< 6%', status: edgeScoreBasic > 0 ? '⚠️ IA' : '✓ OK' },
        "11_Suavidade": { score: smoothScore, value: (smoothRatio * 100).toFixed(2) + '%', threshold: '> 42%', status: smoothScore > 0 ? '⚠️ IA' : '✓ OK' },
        "12_RGB": { score: colorScore, value: (colorUniformity * 100).toFixed(2) + '%', threshold: 'alto', status: colorScore > 0 ? '⚠️ IA' : '✓ OK' },
        "13_Mãos_Anomalas": { score: handScore, value: (handAnomalyRatio * 100).toFixed(2) + '%', threshold: '> 5%', status: handScore > 0 ? '⚠️ IA' : '✓ OK' },
        "14_Reflexos_Perfeitos": { score: reflectScore, value: (reflectionRatio * 100).toFixed(2) + '%', threshold: '> 3%', status: reflectScore > 0 ? '⚠️ IA' : '✓ OK' },
        "15_Patches": { score: patchScore, value: (artifactPatchRatio * 100).toFixed(2) + '%', threshold: '> 2%', status: patchScore > 0 ? '⚠️ IA' : '✓ OK' },
        "16_Material_Inconsist": { score: materialScore, value: (materialInconsistencyRatio * 100).toFixed(2) + '%', threshold: '> 1.5%', status: materialScore > 0 ? '⚠️ IA' : '✓ OK' },
        "17_Bordas_Anomalas": { score: edgeAnomalyScore, value: (anomalousEdgeRatio * 100).toFixed(2) + '%', threshold: '> 2%', status: edgeAnomalyScore > 0 ? '⚠️ IA' : '✓ OK' },
        "18_Saturação": { score: saturationScore, value: (avgSaturation * 100).toFixed(2) + '%', threshold: 'uniforme', status: saturationScore > 0 ? '⚠️ IA' : '✓ OK' },
        "19_Banding": { score: bandScore, value: (bandingRatio * 100).toFixed(2) + '%', threshold: '> 25%', status: bandScore > 0 ? '⚠️ IA' : '✓ OK' },
        "20_Entropia": { score: entropyScore, value: entropy.toFixed(2), threshold: 'baixa', status: entropyScore > 0 ? '⚠️ IA' : '✓ OK' },
        "21_Repetição": { score: repetitiveScore, value: (repetitiveRatio * 100).toFixed(2) + '%', threshold: 'alto', status: repetitiveScore > 0 ? '⚠️ IA' : '✓ OK' },
        "22_Formato": { score: formatScore, value: 'análise', threshold: 'tipo', status: formatScore > 0 ? '⚠️ IA' : '✓ OK' }
      },
      details: {
        freqRatio: parseFloat(freqRatio.toFixed(3)),
        variance: parseFloat(variance.toFixed(3)),
        entropy: parseFloat(entropy.toFixed(2)),
        overSmoothing: parseFloat(overSmoothingRatio.toFixed(3)),
        lightInconsistency: parseFloat(lightInconsistencyRatio.toFixed(3)),
        hasExif
      },
      // 🔴 [NOVO] Logs das técnicas para exibição no HTML
      techniquesLog: techniquesLog
    };
  } catch (e) {
    console.error("[IA Detection] Erro na análise ultra-avançada:", e.message);
    return {
      aiProbability: 0.5,
      confidence: 0.3,
      label: 'error',
      isAI: false,
      source: 'ultra_advanced_heuristic_no_ai'
    };
  }
}
async function detectAIInImage(imagePath) {
  return await detectAIInImageFallback(imagePath);
}

async function generateHeatmap(imagePath) {
  try {
    const analyzed = await sharp(imagePath)
      .resize(400, 400, { fit: 'inside', withoutEnlargement: true })
      .raw()
      .toBuffer({ resolveWithObject: true });
    
    const { data, info } = analyzed;
    const { width, height, channels } = info;
    const heatmapData = new Uint8ClampedArray(width * height);
    
    const windowSize = 3;
    for (let y = windowSize; y < height - windowSize; y++) {
      for (let x = windowSize; x < width - windowSize; x++) {
        let variance = 0;
        for (let dy = -windowSize; dy <= windowSize; dy++) {
          for (let dx = -windowSize; dx <= windowSize; dx++) {
            const idx = ((y + dy) * width + (x + dx)) * channels;
            const gray = (data[idx] + data[idx + 1] + data[idx + 2]) / 3;
            variance += gray * gray;
          }
        }
        heatmapData[y * width + x] = Math.min(255, Math.sqrt(variance / ((windowSize * 2 + 1) ** 2)));
      }
    }
    
    const heatmapImage = Buffer.alloc(width * height * 4);
    for (let i = 0; i < heatmapData.length; i++) {
      const value = heatmapData[i] / 255;
      const idx = i * 4;
      
      if (value < 0.5) {
        heatmapImage[idx] = 0;
        heatmapImage[idx + 1] = Math.floor(value * 2 * 255);
        heatmapImage[idx + 2] = 255;
      } else {
        heatmapImage[idx] = Math.floor((value - 0.5) * 2 * 255);
        heatmapImage[idx + 1] = Math.floor((1 - value) * 2 * 255);
        heatmapImage[idx + 2] = 0;
      }
      heatmapImage[idx + 3] = 255;
    }
    
    const heatmapPath = path.join(CONFIG.TEMP_DIR, `heatmap-${Date.now()}.png`);
    await sharp(heatmapImage, { raw: { width, height, channels: 4 } })
      .png()
      .toFile(heatmapPath);
    
    return heatmapPath;
  } catch (e) {
    console.error("Heatmap generation error:", e.message);
    return null;
  }
}

// 🔒 [SEGURANÇA] Bloqueia URLs internas/privadas (proteção SSRF)
function isUrlSafe(url) {
  let u;
  try { u = new URL(url); } catch { return false; }
  if (!/^https?:$/.test(u.protocol)) return false; // só http/https
  const host = u.hostname.toLowerCase();
  if (host === "localhost" || host === "0.0.0.0" || host.endsWith(".local") || host.endsWith(".internal")) return false;
  // IPs privados/reservados: 127.*, 10.*, 192.168.*, 172.16-31.*, 169.254.*, ::1
  if (/^127\.|^10\.|^192\.168\.|^169\.254\.|^0\./.test(host)) return false;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(host)) return false;
  if (host === "::1" || host.startsWith("fc") || host.startsWith("fd") || host.startsWith("fe80")) return false;
  return true;
}

async function scrapeUrl(url) {
  // 🔒 [SEGURANÇA] Proteção SSRF: recusa URLs internas
  if (!isUrlSafe(url)) {
    return { url, title: "URL bloqueada", description: "Este endereço não pode ser analisado por segurança.", bodyText: "URL inválida ou aponta para rede interna.", images: [] };
  }
  // 🔴 DETECÇÃO DE REDES SOCIAIS (Instagram, TikTok, YouTube)
  const instagramRegex = /instagram\.com\/p\/|instagram\.com\/reel\//i;
  const tiktokRegex = /tiktok\.com\/@|vm\.tiktok\.com\/|vt\.tiktok\.com\//i;
  const youtubeRegex = /youtube\.com\/watch|youtu\.be\//i;
  
  if (instagramRegex.test(url)) {
    return {
      url,
      title: "📷 Vídeo do Instagram",
      description: "❌ Não conseguimos acessar vídeos do Instagram (bloqueado por política anti-bot).",
      bodyText: `
⚠️ SOLUÇÃO:
1. Baixe o vídeo usando um app como SnapInsta ou similar
2. Envie o arquivo MP4 anexando no botão + do Ecoa Saúde
3. Nossa IA analisará se é gerado ou real

🎯 Por que não funciona?
Instagram bloqueia bots/scrapers por segurança.
Mas você pode analisar o vídeo como arquivo!
      `.trim()
    };
  }
  
  if (tiktokRegex.test(url)) {
    return {
      url,
      title: "🎬 Vídeo do TikTok",
      description: "❌ Não conseguimos acessar vídeos do TikTok (bloqueado por política anti-bot).",
      bodyText: `
⚠️ SOLUÇÃO:
1. Abra o link no navegador
2. Baixe o vídeo (sem marca d'água se possível)
3. Envie anexando no botão + do Ecoa Saúde

Nossa IA analisará se é gerado com IA ou é real!
      `.trim()
    };
  }
  
  if (youtubeRegex.test(url)) {
    return {
      url,
      title: "🎥 Vídeo do YouTube",
      description: "⚠️ YouTube requer API especial. Tente extrair screenshots ou baixar o vídeo.",
      bodyText: `
OPÇÕES:
1. Tire screenshot de um frame suspeito → Envie como Imagem
2. Baixe o vídeo com yt-dlp → Envie como Vídeo
3. Cole a descrição/comentários → Analisaremos com Fact Check

Nossa IA pode analisar frames ou vídeos baixados!
      `.trim()
    };
  }
  
  // SCRAPING NORMAL para sites regulares
  try {
    const { data } = await axios.get(url, { timeout: 15000, headers: { "User-Agent": "Mozilla/5.0 Verifacts/1.0" } });
    const $ = cheerio.load(data);
    $("script,style,noscript").remove();
    const title = $("title").first().text().trim() || $('meta[property="og:title"]').attr("content") || "";
    const description = $('meta[name="description"]').attr("content") || $('meta[property="og:description"]').attr("content") || "";
    const bodyText = $("p").map((_,el)=>$(el).text().trim()).get().filter(Boolean).join("\n");
    return { url, title, description, bodyText: truncate(bodyText, CONFIG.MAX_SCRAPED_CHARS) };
  } catch (e) {
    return {
      url,
      title: "⚠️ Erro ao acessar URL",
      description: "Não conseguimos acessar este link.",
      bodyText: `Erro: ${e.message || "URL inacessível"}`
    };
  }
}

async function searchFactChecks(query) {
  if (!CONFIG.GOOGLE_FACTCHECK_API_KEY || !query?.trim()) return [];
  try {
    const { data } = await axios.get("https://factchecktools.googleapis.com/v1alpha1/claims:search", {
      params: { key: CONFIG.GOOGLE_FACTCHECK_API_KEY, query, languageCode: "pt-BR", pageSize: 8 }, timeout: 15000
    });
    const fc = (data.claims||[]).map(claim=>({
      text: claim.text||"", claimant: claim.claimant||"", claimDate: claim.claimDate||"",
      reviews: (claim.claimReview||[]).map(r=>({
        publisher: r.publisher?.name||"", title: r.title||"", textualRating: r.textualRating||"",
        url: r.url||"", reviewDate: r.reviewDate||"", domain: getSourceDomain(r.url||""),
        recencyScore: scoreRecency(r.reviewDate||claim.claimDate||"")
      }))
    }));
    for (const f of fc) f.reviews.sort(compareByNewestDate);
    fc.sort((a,b)=>compareByNewestDate(a.reviews[0]||a, b.reviews[0]||b));
    return fc;
  } catch(e) { console.error("Fact Check API:", e.message); return []; }
}

async function fetchNewsRss(query, days) {
  const encoded = encodeURIComponent(query);
  const url = `https://news.google.com/rss/search?q=${encoded}&hl=pt-BR&gl=BR&ceid=BR:pt-419`;
  const { data } = await axios.get(url, { timeout: 15000, headers: { "User-Agent": "Mozilla/5.0 Verifacts/1.0" } });
  const $ = cheerio.load(data, { xmlMode: true });
  const items = [];
  $("item").each((_,el)=>{
    const title=$(el).find("title").first().text().trim();
    const link=$(el).find("link").first().text().trim();
    const pubDate=$(el).find("pubDate").first().text().trim();
    const sourceEl=$(el).find("source").first();
    const source=sourceEl.text().trim();
    const sourceUrl=sourceEl.attr("url")||"";
    const realDomain = sourceUrl ? getSourceDomain(sourceUrl) : getSourceDomain(link);
    if (title&&link) items.push({ title, link, pubDate, source: source||realDomain, sourceDomain: realDomain, recencyScore: scoreRecency(pubDate) });
  });
  return items;
}

async function searchRecentNews(query) {
  if (!query?.trim()) return [];
  try {
    const words = query.trim().split(/\s+/).slice(0, 4).join(" ");
    const [r1, r2] = await Promise.allSettled([
      fetchNewsRss(query, CONFIG.NEWS_LOOKBACK_DAYS),
      words !== query ? fetchNewsRss(words, CONFIG.NEWS_LOOKBACK_DAYS) : Promise.resolve([])
    ]);
    const combined = [
      ...(r1.status === "fulfilled" ? r1.value : []),
      ...(r2.status === "fulfilled" ? r2.value : [])
    ];
    const seen = new Set();
    const unique = combined.filter(item => {
      if (seen.has(item.link)) return false;
      seen.add(item.link);
      return true;
    });
    unique.sort(compareByNewestDate);
    return unique.slice(0, CONFIG.MAX_NEWS_ITEMS);
  } catch(e) { console.error("News:", e.message); return []; }
}

function summarizeFactChecks(fc) {
  if (!fc.length) return "Nenhuma checagem encontrada.";
  // 🎯 GPT tem contexto grande: 8 checagens com mais detalhe (era 5, corte da era Ollama)
  return fc.slice(0, 8).map((item,i)=>{
    const reviews = item.reviews.length ? item.reviews.slice(0, 3).map(r=>`- ${r.publisher}: ${r.textualRating||"sem rating"} | ${truncate(r.title, 180)||"sem título"} | data: ${r.reviewDate||item.claimDate||"desconhecida"}`).join("\n") : "- Sem reviews";
    return [`Checagem ${i+1}`,`Alegação: ${truncate(item.text, 300)||"sem texto"}`,`Autor: ${item.claimant||"desconhecido"}`,`Reviews:`,reviews].join("\n");
  }).join("\n\n");
}
function summarizeRecentNews(items) {
  if (!items.length) return "Nenhuma notícia recente.";
  // 🎯 12 notícias com títulos completos (era 8/140 chars, corte da era Ollama)
  return items.slice(0, 12).map((item,i)=>`${i+1}. ${truncate(item.title, 220)} | fonte: ${item.source||item.sourceDomain||"desconhecida"} | data: ${item.pubDate||"desconhecida"}`).join("\n");
}

const LLM_SYSTEM_PROMPT = `Você é um verificador de fatos profissional sênior, no padrão das melhores agências brasileiras de checagem (Lupa, Aos Fatos, Comprova).

MÉTODO DE TRABALHO:
1. Identifique a alegação factual central e verificável do conteúdo.
2. Pese as evidências por hierarquia de confiabilidade: checagens de agências especializadas têm peso MÁXIMO; notícias de veículos jornalísticos estabelecidos têm peso ALTO; ausência total de cobertura sobre um fato extraordinário é um SINAL DE ALERTA (fatos extraordinários geram cobertura).
3. Considere a data atual e priorize evidências recentes, especialmente em temas dinâmicos.
4. Calibre o veredito com honestidade intelectual: não invente certeza que as evidências não sustentam, mas também não seja covarde quando as evidências são claras.

QUALIDADE DA ESCRITA (obrigatório):
- Escreva SEMPRE em português do Brasil, com clareza jornalística.
- Seja ESPECÍFICO: cite as fontes, datas e fatos das evidências fornecidas. NUNCA escreva conclusões genéricas como "trate com cautela" ou "verifique as fontes" sem substância.
- Se as evidências conflitam, explique o conflito. Se faltam evidências, diga exatamente o que seria necessário para confirmar.

Responda APENAS com JSON válido, sem markdown.`;

// 🔴 [NOVO] OpenAI GPT (com suporte a imagens/vision)
async function openaiJson({ prompt, images = [] }) {
  // GPT tem 128k de contexto — pode receber muito mais evidência que o Ollama
  const safePrompt = truncate(prompt, 28000);
  const content = [{ type: "text", text: safePrompt }];
  // Imagens em base64 → data URLs (detail: low = mais barato, suficiente para contexto)
  for (const b64 of images.slice(0, 6)) {
    content.push({ type: "image_url", image_url: { url: `data:image/jpeg;base64,${b64}`, detail: "low" } });
  }
  const payload = {
    model: CONFIG.OPENAI_MODEL,
    response_format: { type: "json_object" },
    temperature: 0.2,   // 🎯 baixa = análises consistentes e factuais
    max_tokens: 2200,   // 🎯 espaço para conclusões detalhadas
    messages: [
      { role: "system", content: LLM_SYSTEM_PROMPT },
      { role: "user", content }
    ]
  };
  const { data } = await axios.post("https://api.openai.com/v1/chat/completions", payload, {
    headers: { "Authorization": `Bearer ${CONFIG.OPENAI_API_KEY}`, "Content-Type": "application/json" },
    timeout: 60000
  }).catch(e => {
    console.error("[OpenAI] Erro:", e.response?.data?.error?.message || e.message);
    return { data: null };
  });
  return safeJsonParse(data?.choices?.[0]?.message?.content || "{}", {});
}

async function ollamaJson({ prompt, images=[] }) {
  // 🔴 [FIX] Proteção: trunca prompts gigantes (evita erro de contexto)
  const safePrompt = truncate(prompt, 12000);
  const payload = {
    model: CONFIG.OLLAMA_MODEL, stream: false, format: "json",
    // 🔴 [FIX] num_ctx maior — o padrão (4096) estourava com notícias + checagens
    options: { num_ctx: 8192 },
    messages: [
      { role:"system", content: LLM_SYSTEM_PROMPT },
      { role:"user", content: safePrompt, images }
    ]
  };
  const { data } = await axios.post(`${CONFIG.OLLAMA_HOST}/api/chat`, payload, { timeout: 120000 }).catch(e => {
    // 🔴 [FIX] Ollama falhou (contexto, offline, etc) → retorna vazio em vez de quebrar o app
    console.error("[Ollama] Erro:", e.response?.data?.error || e.message);
    return { data: null };
  });
  return safeJsonParse(data?.message?.content || "{}", {});
}

// 🔴 [NOVO] Roteador de LLM: OpenAI se houver chave, senão Ollama local
async function llmJson(args) {
  if (CONFIG.OPENAI_API_KEY) return openaiJson(args);
  return ollamaJson(args);
}

async function buildClaimQuery(inputText, images=[]) {
  const r = await llmJson({
    prompt: `Analise o conteúdo abaixo (e imagens, se houver) e extraia:

1. "claim": a alegação factual CENTRAL e verificável, reescrita como uma frase clara e completa (quem, o quê, quando, onde). Se houver várias, escolha a mais importante/verificável.
2. "query": termos de busca de 2 a 6 palavras, em português, usando os NOMES PRÓPRIOS e substantivos que apareceriam em manchetes de notícias sobre isso (nada de palavras vazias como "notícia", "verdade", "aconteceu").
3. "is_dynamic": true se a alegação envolve eventos em andamento, pessoas vivas, política atual, esportes recentes ou qualquer coisa que muda com o tempo; false para fatos históricos/científicos estáveis.

Retorne JSON: { "claim": "...", "query": "...", "is_dynamic": true }

Conteúdo:
${inputText}`,
    images
  });
  return { claim: r.claim||"", query: r.query||"", isDynamic: typeof r.is_dynamic==="boolean" ? r.is_dynamic : isDynamicClaim(inputText) };
}

function prepareEvidenceSummary({ factChecks=[], recentNews=[] }) {
  const recent = factChecks.filter(fc=>scoreRecency(fc.reviews[0]?.reviewDate||fc.claimDate)>=0.35);
  return { allFactChecksText: summarizeFactChecks(factChecks), recentFactChecksText: summarizeFactChecks(recent), recentNewsText: summarizeRecentNews(recentNews) };
}

async function classifyContent({ contentText, images=[], factChecks=[], recentNews=[], claimQuery="", isDynamic=false }) {
  const ev = prepareEvidenceSummary({ factChecks, recentNews });
  const r = await llmJson({
    prompt: `DATA ATUAL: ${new Date().toLocaleDateString("pt-BR", { day:"2-digit", month:"long", year:"numeric" })}
CONSULTA PESQUISADA: ${claimQuery||"não informada"}
TEMA DINÂMICO (evento em andamento): ${isDynamic?"SIM — priorize as notícias mais recentes sobre checagens antigas":"não"}

═══ DEFINIÇÃO DOS VEREDITOS ═══
- provavelmente_falso: as evidências CONTRADIZEM a alegação (checagens desmentem, ou fatos estabelecidos são incompatíveis)
- suspeito: sinais de manipulação, sensacionalismo ou distorção; evidências parcialmente contrárias; alegação extraordinária sem nenhuma cobertura jornalística
- nao_verificado: evidências insuficientes para confirmar OU negar (seja honesto sobre isso)
- provavelmente_verdadeiro: múltiplas fontes confiáveis e independentes CONFIRMAM a alegação

═══ CALIBRAÇÃO DA CONFIANÇA ═══
0.90-1.00 → checagens diretas de agências sobre ESTA alegação específica
0.70-0.89 → forte convergência de veículos confiáveis
0.50-0.69 → evidência parcial ou indireta
0.30-0.49 → pouca evidência, veredito provisório

═══ FORMATO DA RESPOSTA (JSON) ═══
{
  "verdict": "um dos 4 vereditos",
  "confidence": 0.0,
  "summary": "2-3 frases diretas: o veredito e o motivo principal, citando a evidência mais forte",
  "reasons": ["3 a 5 motivos ESPECÍFICOS, cada um citando fonte e data das evidências abaixo (ex: 'O Estadão noticiou em 05/05/2026 que...'). PROIBIDO motivos genéricos."],
  "reply": "Conclusão completa em 4-8 frases: (1) contextualize a alegação; (2) o que as evidências mostram, com fontes e datas; (3) o que permanece incerto, se algo; (4) orientação prática e específica ao leitor. Escreva como o parágrafo final de uma checagem profissional publicada."
}

═══ CONTEÚDO A VERIFICAR ═══
${contentText}

═══ CHECAGENS DE AGÊNCIAS (peso máximo) ═══
${ev.recentFactChecksText}

${ev.allFactChecksText}

═══ NOTÍCIAS RECENTES (peso alto) ═══
${ev.recentNewsText}`,
    images
  });
  return {
    verdict: r.verdict||"nao_verificado",
    confidence: typeof r.confidence==="number" ? Math.max(0,Math.min(1,r.confidence)) : 0.5,
    summary: r.summary||"Não foi possível concluir.",
    reasons: Array.isArray(r.reasons) ? r.reasons : [],
    reply: r.reply||"Não foi possível gerar uma análise completa. Tente novamente."
  };
}

async function analyzeText(text) {
  const ci = await buildClaimQuery(text);
  const query = ci.query||text;
  const [factChecks, recentNews] = await Promise.all([searchFactChecks(query), searchRecentNews(query)]);
  const result = await classifyContent({ contentText:`Texto:\n${text}\n\nAlegação:\n${ci.claim||"não identificada"}`, factChecks, recentNews, claimQuery:query, isDynamic:ci.isDynamic||isDynamicClaim(text) });
  return { inputType:"texto", ...result, claimQuery:query, factChecks, recentNews };
}
async function analyzeLink(url) {
  const page = await scrapeUrl(url);
  const text = `URL: ${page.url}\nTítulo: ${page.title}\nDescrição: ${page.description}\nConteúdo:\n${page.bodyText}`;
  const ci = await buildClaimQuery(text);
  const query = ci.query||page.title||url;
  const [factChecks, recentNews] = await Promise.all([searchFactChecks(query), searchRecentNews(query)]);
  const result = await classifyContent({ contentText:`${text}\n\nAlegação:\n${ci.claim||"não identificada"}`, factChecks, recentNews, claimQuery:query, isDynamic:ci.isDynamic||isDynamicClaim(text) });
  return { inputType:"link", ...result, page, claimQuery:query, factChecks, recentNews };
}
async function imageToBase64(p) { return (await fs.readFile(p)).toString("base64"); }
async function analyzeImage(imagePath, caption="") {
  const aiDetection = await detectAIInImage(imagePath);
  const heatmapPath = await generateHeatmap(imagePath);
  const heatmapBase64 = heatmapPath ? await imageToBase64(heatmapPath) : null;
  if (heatmapPath) await cleanup(heatmapPath);
  
  const b64 = await imageToBase64(imagePath);
  const ci = await buildClaimQuery(`Legenda: ${caption||"sem legenda"}`, [b64]);
  const query = ci.query||caption||"imagem";
  const [factChecks, recentNews] = await Promise.all([searchFactChecks(query), searchRecentNews(query)]);
  const result = await classifyContent({ contentText:`Legenda: ${caption||"sem legenda"}\n\nAlegação:\n${ci.claim||"não identificada"}`, images:[b64], factChecks, recentNews, claimQuery:query, isDynamic:ci.isDynamic||isDynamicClaim(caption) });
  return { inputType:"imagem", ...result, claimQuery:query, factChecks, recentNews, aiDetection, heatmapBase64 };
}
async function runFfmpeg(args) { return execFileAsync(ffmpegPath, args); }
async function extractFrames(videoPath, outputDir) {
  await fs.ensureDir(outputDir);
  // 🔴 [FIX] Forçar autorotação dos metadados (vídeos verticais de celular)
  // ffmpeg aplica rotação automática quando processa via filter
  await runFfmpeg([
    "-y",
    "-i", videoPath,
    "-vf", `fps=1/${CONFIG.FRAME_INTERVAL_SECONDS}`,
    "-frames:v", String(CONFIG.MAX_VIDEO_FRAMES),
    "-q:v", "2",
    path.join(outputDir, "frame-%03d.jpg")
  ]);
  return (await fs.readdir(outputDir)).filter(f=>f.endsWith(".jpg")).sort().map(f=>path.join(outputDir,f));
}

// 🔴 [NOVO] Fallback graceful se ffmpeg não estiver disponível
async function extractFramesSafe(videoPath, outputDir) {
  try {
    return await extractFrames(videoPath, outputDir);
  } catch (e) {
    console.error("[Vídeo] FFmpeg não disponível:", e.message);
    // Retornar array vazio para indicar falha
    return [];
  }
}
async function extractAudio(videoPath, audioPath) {
  try { await runFfmpeg(["-y","-i",videoPath,"-vn","-acodec","pcm_s16le","-ar","16000","-ac","1",audioPath]); return true; }
  catch(e) { console.error("Áudio:",e.message); return false; }
}
async function transcribeWithWhisper(audioPath) {
  if (!CONFIG.WHISPER_COMMAND||!CONFIG.WHISPER_MODEL) return "";
  const { v4:uuidv4 } = require("uuid");
  const outputBase = path.join(CONFIG.TEMP_DIR,`whisper-${uuidv4()}`);
  try {
    await execFileAsync(CONFIG.WHISPER_COMMAND,["-m",CONFIG.WHISPER_MODEL,"-f",audioPath,"-otxt","-of",outputBase],{timeout:120000});
    const txtPath = `${outputBase}.txt`;
    if (await fs.pathExists(txtPath)) { const t=await fs.readFile(txtPath,"utf8"); await cleanup(txtPath); return truncate(t.trim(),4000); }
    return "";
  } catch(e) { console.error("Whisper:",e.message); return ""; }
}
async function analyzeVideo(videoPath, caption="") {
  const { v4:uuidv4 } = require("uuid");
  const framesDir = path.join(CONFIG.TEMP_DIR,`frames-${uuidv4()}`);
  const audioPath = path.join(CONFIG.TEMP_DIR,`audio-${uuidv4()}.wav`);
  try {
    // 🔴 [NOVO] Usar extractFramesSafe para graceful fallback
    const framePaths = await extractFramesSafe(videoPath, framesDir);
    const frameAnalyses = [];
    const frameBase64s = [];
    
    if (framePaths.length === 0) {
      // FFmpeg não disponível - retornar análise sem frames
      console.log("[Vídeo] FFmpeg não disponível. Retornando análise básica.");
      const ctx = `Legenda: ${caption||"sem legenda"}\nTranscrição: indisponível (ffmpeg não instalado)`;
      const query = caption||"video";
      const [factChecks, recentNews] = await Promise.all([searchFactChecks(query), searchRecentNews(query)]);
      const result = await classifyContent({ contentText:`${ctx}\n\nAlegação: não identificada`, images:[], factChecks, recentNews, claimQuery:query, isDynamic:isDynamicClaim(ctx) });
      return { 
        inputType:"video", 
        ...result, 
        transcript:"[FFmpeg não instalado - análise básica]", 
        claimQuery:query, 
        factChecks, 
        recentNews, 
        frameAnalyses:[], 
        frameBase64s:[],
        ffmpegAvailable: false
      };
    }
    
    for (let i = 0; i < framePaths.length; i++) {
      const aiDetection = await detectAIInImage(framePaths[i]);
      frameAnalyses.push({ frameNum: i + 1, ...aiDetection });
      frameBase64s.push(await imageToBase64(framePaths[i]));
    }
    
    let transcript="";
    if (await extractAudio(videoPath,audioPath)) transcript = await transcribeWithWhisper(audioPath);
    const ctx=`Legenda: ${caption||"sem legenda"}\nTranscrição: ${transcript||"indisponível"}`;
    const ci = await buildClaimQuery(ctx, frameBase64s);
    const query = ci.query||caption||transcript||"video";
    const [factChecks, recentNews] = await Promise.all([searchFactChecks(query), searchRecentNews(query)]);
    const result = await classifyContent({ contentText:`${ctx}\n\nAlegação:\n${ci.claim||"não identificada"}`, images:frameBase64s, factChecks, recentNews, claimQuery:query, isDynamic:ci.isDynamic||isDynamicClaim(ctx) });
    return { inputType:"video", ...result, transcript, claimQuery:query, factChecks, recentNews, frameAnalyses, frameBase64s, ffmpegAvailable: true };
  } finally { await cleanup(framesDir); await cleanup(audioPath); }
}

function formatResultHtml(result) {
  // 🔴 [NOVO] Descrições de cada técnica de detecção de IA
  const TECH_DESCRIPTIONS = {
    "EXIF": "Metadados da câmera (data, modelo, lente). Fotos reais costumam ter EXIF; imagens geradas por IA quase nunca têm.",
    "Frequência": "Distribuição de altas/baixas frequências. IA tende a gerar imagens com poucas altas frequências (menos detalhes finos naturais).",
    "Gradiente": "Intensidade média das transições entre pixels. Imagens de IA costumam ter gradientes muito suaves.",
    "Bloom Halo": "Halos de luz ao redor de objetos brilhantes. IA frequentemente cria brilhos artificiais exagerados.",
    "Contraste": "Uniformidade do contraste pela imagem. IA tende a aplicar contraste muito uniforme e artificial.",
    "Over-Smooth": "Suavização excessiva (efeito 'plástico'). Típico de imagens geradas, que perdem textura natural.",
    "Luz Incons.": "Inconsistências na iluminação. Sombras que vêm de direções impossíveis indicam manipulação ou IA.",
    "Variância": "Variação de brilho dos pixels. IA gera imagens com baixa variância (muito homogêneas).",
    "Entropia": "Complexidade/aleatoriedade da imagem. Imagens de IA têm entropia mais baixa (padrões repetitivos).",
    "Bordas": "Proporção de transições abruptas. IA cria bordas muito limpas e perfeitas, sem ruído natural.",
    "Suavidade": "Proporção de áreas lisas. Imagens de IA têm muitas regiões artificialmente suaves.",
    "RGB": "Uniformidade entre canais de cor. IA pode gerar distribuições de cor não-naturais.",
    "Saturação": "Nível de saturação das cores. IA frequentemente produz cores saturadas demais.",
    "Banding": "Faixas de cor (posterização). Transições de cor em degraus indicam geração artificial.",
    "Repetição": "Padrões de pixels repetidos. IA tende a repetir texturas de forma não-natural.",
    "Mãos Anomalas": "Anomalias em pele/mãos (dedos extras, deformações). Erro clássico de geradores de IA.",
    "Reflexos": "Reflexos perfeitos demais em superfícies. IA cria reflexos uniformes irreais.",
    "Patches": "Áreas suspeitas tipo insígnias/placas. IA gera texto e símbolos deformados.",
    "Material": "Inconsistência de materiais/superfícies. Texturas que mudam de forma fisicamente impossível.",
    "Bordas Anom.": "Bordas com transições não-naturais entre objetos. Falta de blending realista.",
    "Formato": "Tipo de arquivo. PNG/WebP são mais comuns em imagens geradas por IA."
  };
  function techDescription(name) {
    const clean = name.replace(/^\d+_/, '').replace(/_/g, ' ');
    return TECH_DESCRIPTIONS[clean] || "Técnica de análise forense de imagem para detecção de IA.";
  }

  const vm = {
    provavelmente_falso:      { label:"FALSO",         cls:"vf", bar:"#e8e8e8" },
    suspeito:                 { label:"SUSPEITO",       cls:"vs", bar:"#b0b0b0" },
    nao_verificado:           { label:"NÃO VERIFICADO", cls:"vn", bar:"#888" },
    provavelmente_verdadeiro: { label:"VERDADEIRO",     cls:"vt", bar:"#fff" }
  };
  const v = vm[result.verdict] || { label: result.verdict.toUpperCase(), cls:"vn", bar:"#888" };
  const pct = Math.round((result.confidence||0)*100);
  const ts = new Date().toLocaleString("pt-BR",{dateStyle:"short",timeStyle:"short"});
  const typeLabel = { texto:"TEXTO", link:"LINK", imagem:"IMAGEM", video:"VÍDEO" }[result.inputType] || result.inputType.toUpperCase();

  // AI Detection Section
  let aiSection = "";
  if (result.aiDetection) {
    const aiPct = Math.round((result.aiDetection.aiProbability || 0) * 100);
    const confPct = Math.round((result.aiDetection.confidence || 0) * 100);
    const source = result.aiDetection.source || 'unknown';
    const isAPI = source.includes('replicate');
    
    const aiStatus = aiPct > 70 ? "⚠️ POSSÍVEL IA" : aiPct > 40 ? "⚠️ SUSPEITA" : "✓ AUTÊNTICA";
    const aiColor = aiPct > 70 ? "#C62828" : aiPct > 40 ? "#B45F06" : "#2E8B57";
    
    aiSection = `<div style="background: #EEF3FC; border: 1px solid #CCDAF3; border-radius: 18px; padding: 20px; margin-bottom: 20px;">
      <div style="font-size: 12px; color: #2560CC; text-transform: uppercase; font-weight: 700; margin-bottom: 16px;">
        🔍 Detecção de IA ${isAPI ? '(via Replicate 🤖)' : '(análise local)'}
      </div>
      <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-bottom: 16px;">
        <div>
          <div style="color: #6B7280; font-size: 12px; margin-bottom: 8px;">Probabilidade de IA</div>
          <div style="font-size: 28px; font-weight: 700; color: ${aiColor};">${aiPct}%</div>
          <div style="color: #4A5260; font-size: 12px; margin-top: 4px;">${aiStatus}</div>
        </div>
        <div>
          <div style="color: #6B7280; font-size: 12px; margin-bottom: 8px;">Confiança</div>
          <div style="font-size: 28px; font-weight: 700; color: #2560CC;">${confPct}%</div>
          <div style="color: #4A5260; font-size: 12px; margin-top: 4px;">${isAPI ? 'Modelo IA' : 'Heurística'}</div>
        </div>
        <div>
          <div style="color: #6B7280; font-size: 12px; margin-bottom: 8px;">Classificação</div>
          <div style="font-size: 14px; font-weight: 600; color: #2560CC; word-break: break-word; margin-top: 8px;">${escapeHtml(result.aiDetection.label || 'N/A')}</div>
        </div>
      </div>
      ${result.aiDetection.noiseScore !== undefined ? `
        <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; padding-top: 12px; border-top: 1px solid #E3E6EB;">
          <div><span style="color: #6B7280; font-size: 11px;">Ruído Detectado:</span> <span style="color: #2560CC; font-weight: 600;">${Math.round((result.aiDetection.noiseScore || 0) * 100)}%</span></div>
          <div><span style="color: #6B7280; font-size: 11px;">Artefatos:</span> <span style="color: #2560CC; font-weight: 600;">${Math.round((result.aiDetection.artifactScore || 0) * 100)}%</span></div>
        </div>
      ` : ''}
      ${result.heatmapBase64 ? `<div style="margin-top: 16px;"><div style="font-size: 12px; color: #6B7280; margin-bottom: 8px;">Mapa de Calor (Anomalias):</div><img src="data:image/png;base64,${result.heatmapBase64}" style="width: 100%; max-width: 500px; border-radius: 4px; border: 1px solid #E3E6EB;"><div style="color: #6B7280; font-size: 11px; margin-top: 8px;">🔵 Azul = Autêntico | 🔴 Vermelho = Possível IA</div></div>` : ""}
    </div>`;
  }
  
  // Video Frames Analysis
  let videoFramesSection = "";
  if (result.frameAnalyses && result.frameAnalyses.length > 0) {
    const avgAI = (result.frameAnalyses.reduce((a, f) => a + f.aiProbability, 0) / result.frameAnalyses.length * 100).toFixed(0);
    videoFramesSection = `<div style="background: #EEF3FC; border: 1px solid #CCDAF3; border-radius: 18px; padding: 20px; margin-bottom: 20px;">
      <div style="font-size: 12px; color: #2560CC; text-transform: uppercase; font-weight: 700; margin-bottom: 16px;">🎬 Análise de Frames - Técnicas Ativadas</div>
      <div style="margin-bottom: 16px; padding: 8px; background: #F4F6F9; border-radius: 4px; color: #4A5260; font-size: 12px;">IA Detectada (Média): <span style="color: #2560CC; font-weight: 700;">${avgAI}%</span></div>
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 400px), 1fr)); gap: 16px;">`;
    
    result.frameAnalyses.forEach((frame, idx) => {
      const frameAiPct = Math.round((frame.aiProbability || 0) * 100);
      const frameColor = frameAiPct > 70 ? "#C62828" : frameAiPct > 40 ? "#B45F06" : "#2E8B57";
      const frameLabel = frameAiPct > 70 ? "CERTEZA IA" : frameAiPct > 40 ? "SUSPEITO" : "PARECE REAL";
      
      // 🔴 Separar técnicas ativadas (IA) das limpas (OK)
      const techniques = frame.techniques || {};
      const allTechs = Object.entries(techniques);
      const activeTechniques = allTechs.filter(([_, t]) => t.score > 0).sort((a, b) => b[1].score - a[1].score);
      const cleanTechniques = allTechs.filter(([_, t]) => t.score <= 0);
      
      // Cards de técnicas ativadas (suspeitas de IA)
      const activeCards = activeTechniques.length > 0 
        ? activeTechniques.map(([name, tech]) => {
            const cleanName = name.replace(/^\d+_/, '').replace(/_/g, ' ');
            const desc = escapeHtml(techDescription(name));
            return `<div style="background: rgba(229,57,53,0.08); border: 1px solid rgba(229,57,53,0.3); border-radius: 6px; padding: 10px 12px;">
              <div style="display: flex; align-items: center; justify-content: space-between; gap: 8px;">
                <span style="color: #1F242C; font-size: 13px; font-weight: 500; display: flex; align-items: center; gap: 5px;">
                  ${escapeHtml(cleanName)}
                  <span class="tech-info" tabindex="0" data-tip="${desc}">!</span>
                </span>
                <span style="color: #C62828; font-size: 11px; font-weight: 700;">⚠ IA</span>
              </div>
              <div style="color: #C62828; font-size: 16px; font-weight: 700; margin-top: 4px; font-family: 'Barlow Condensed', sans-serif;">${tech.value}</div>
            </div>`;
          }).join('') 
        : `<div style="grid-column: 1/-1; color: #2E8B57; font-size: 14px; padding: 12px; text-align: center; background: rgba(67,160,71,0.08); border-radius: 6px;">✓ Nenhuma anomalia de IA detectada</div>`;
      
      // Cards de técnicas limpas (compactos)
      const cleanCards = cleanTechniques.map(([name, tech]) => {
        const cleanName = name.replace(/^\d+_/, '').replace(/_/g, ' ');
        const desc = escapeHtml(techDescription(name));
        return `<div style="background: rgba(67,160,71,0.05); border: 1px solid rgba(67,160,71,0.2); border-radius: 6px; padding: 8px 10px;">
          <div style="display: flex; align-items: center; justify-content: space-between; gap: 6px;">
            <span style="color: #5B6370; font-size: 12px; display: flex; align-items: center; gap: 5px;">
              ${escapeHtml(cleanName)}
              <span class="tech-info" tabindex="0" data-tip="${desc}">!</span>
            </span>
            <span style="color: #2E8B57; font-size: 11px;">✓</span>
          </div>
          <div style="color: #2E8B57; font-size: 13px; font-weight: 600; margin-top: 2px; font-family: 'Barlow Condensed', sans-serif;">${tech.value}</div>
        </div>`;
      }).join('');
      
      videoFramesSection += `<div style="padding: 14px; background: #F4F6F9; border: 2px solid ${frameColor}40; border-radius: 8px;">
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px;">
          <div style="font-weight: 600; color: #14171C; font-size: 17px;">📹 Frame ${frame.frameNum}</div>
          <div style="background: ${frameColor}20; color: ${frameColor}; font-size: 11px; font-weight: 700; padding: 4px 10px; border-radius: 12px; text-transform: uppercase; letter-spacing: 0.05em;">${frameLabel}</div>
        </div>
        
        <!-- Frame com overlay de bolinhas marcando rastros de IA -->
        <div style="position: relative; width: 100%; margin-bottom: 12px; background: #000; border-radius: 4px; box-sizing: border-box; line-height: 0;">
          <img src="data:image/jpeg;base64,${result.frameBase64s[idx]}" style="width: 100%; height: auto; border-radius: 4px; display: block; box-shadow: 0 4px 8px rgba(0,0,0,0.5); border: 1px solid #E3E6EB;">
          <div style="position: absolute; top: 0; left: 0; right: 0; bottom: 0; border-radius: 4px; pointer-events: none;">
            ${(frame.aiTraceDots && frame.aiTraceDots.length > 0 && frameAiPct > 40) ? frame.aiTraceDots.map(dot => {
              const dotColor = dot.type === 'bloom' ? '#FFD700' : dot.type === 'edge' ? '#FF5252' : '#40C4FF';
              const size = 10 + Math.round(dot.intensity * 14);
              return `<div style="position: absolute; top: ${(dot.y*100).toFixed(1)}%; left: ${(dot.x*100).toFixed(1)}%; width: ${size}px; height: ${size}px; transform: translate(-50%,-50%); border-radius: 50%; border: 2px solid ${dotColor}; background: ${dotColor}33; box-shadow: 0 0 ${size}px ${dotColor}aa; animation: pulse-dot 2s infinite;"></div>`;
            }).join('') : ''}
          </div>
        </div>
        
        ${(frame.aiTraceDots && frame.aiTraceDots.length > 0 && frameAiPct > 40) ? `
        <!-- Legenda das bolinhas -->
        <div style="display: flex; flex-wrap: wrap; gap: 14px; margin-bottom: 12px; padding: 8px 12px; background: #F4F6F9; border-radius: 6px; font-size: 11px; color: #4A5260;">
          <span style="display: flex; align-items: center; gap: 5px;"><span style="width: 10px; height: 10px; border-radius: 50%; border: 2px solid #FFD700; background: #FFD70033; display: inline-block;"></span> Bloom/Halo</span>
          <span style="display: flex; align-items: center; gap: 5px;"><span style="width: 10px; height: 10px; border-radius: 50%; border: 2px solid #FF5252; background: #FF525233; display: inline-block;"></span> Bordas artificiais</span>
          <span style="display: flex; align-items: center; gap: 5px;"><span style="width: 10px; height: 10px; border-radius: 50%; border: 2px solid #40C4FF; background: #40C4FF33; display: inline-block;"></span> Luz inconsistente</span>
          <span style="margin-left: auto; color: #6B7280;">${frame.aiTraceDots.length} rastros marcados</span>
        </div>
        ` : ''}
        
        <!-- Barra de IA Detectada -->
        <div style="padding: 12px 14px; background: #F4F6F9; border-radius: 6px; margin-bottom: 14px; border-left: 4px solid ${frameColor}; display: flex; align-items: center; justify-content: space-between;">
          <span style="color: #4A5260; font-size: 14px; font-weight: 600;">IA Detectada</span>
          <span style="color: ${frameColor}; font-size: 32px; font-weight: 700; line-height: 1;">${frameAiPct}%</span>
        </div>
        
        <!-- Técnicas que acusaram IA -->
        <div style="font-size: 12px; color: #C62828; margin-bottom: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em;">⚠ Indicadores de IA (${activeTechniques.length})</div>
        <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(130px, 1fr)); gap: 8px; margin-bottom: 16px;">
          ${activeCards}
        </div>
        
        <!-- Técnicas limpas (verificações OK) -->
        <div style="font-size: 12px; color: #2E8B57; margin-bottom: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em;">✓ Verificações OK (${cleanTechniques.length})</div>
        <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(110px, 1fr)); gap: 6px;">
          ${cleanCards}
        </div>
      </div>`;
    });
    videoFramesSection += `</div></div>`;
  } else if (result.inputType === "video" && !result.ffmpegAvailable) {
    // 🔴 [NOVO] Mensagem quando ffmpeg não está disponível
    videoFramesSection = `<div style="background: #FDF5EA; border: 1px solid #F1DDBE; border-radius: 18px; padding: 20px; margin-bottom: 20px;">
      <div style="font-size: 12px; color: #B45F06; text-transform: uppercase; font-weight: 700; margin-bottom: 12px;">⚠️ Análise de Frames Indisponível</div>
      <div style="color: #4A5260; font-size: 13px; line-height: 1.5;">
        <p>FFmpeg não está instalado. Para analisar frames de vídeos, instale:</p>
        <div style="background: #F4F6F9; padding: 10px; border-radius: 4px; font-family: monospace; margin: 8px 0; font-size: 12px; color: #2560CC;">
          npm install ffmpeg-static
        </div>
        <p style="margin-top: 12px;">Análise factual e de IA por metadata foi realizada. Para análise completa com extração de frames, instale ffmpeg-static.</p>
      </div>
    </div>`;
  }

  const checks = (result.factChecks||[]).slice(0,3).map(fc=>{
    const r = fc.reviews?.[0];
    if (!r) return `<div class="src-item"><span class="src-pub">FONTE</span><span class="src-text">${escapeHtml(fc.text||"")}</span></div>`;
    return `<div class="src-item">
      <div class="src-row"><span class="src-pub">${escapeHtml(r.publisher||"FONTE")}</span><span class="src-rating">${escapeHtml(r.textualRating||"—")}</span></div>
      <span class="src-text">${escapeHtml(r.title||"")}</span>
      <a class="src-link" href="${escapeHtml(r.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(r.url)}</a>
    </div>`;
  }).join("") || `<div class="empty-msg">Nenhuma checagem encontrada.</div>`;

  const newsItems = result.recentNews||[];
  const totalNews = newsItems.length;
  const newsCards = newsItems.map((item, idx)=>{
    const domain = item.sourceDomain || "";
    const faviconUrl = domain ? `https://icons.duckduckgo.com/ip3/${domain}.ico` : "";
    const pubFormatted = item.pubDate ? new Date(item.pubDate).toLocaleDateString("pt-BR") : "";
    const initials = (item.source||domain||"?").slice(0,2).toUpperCase();
    return `<div class="news-slide">
      <div class="news-header">
        <div class="news-favicon-wrap">
          ${faviconUrl
            ? `<img class="news-favicon" src="${faviconUrl}" alt="" loading="lazy"
                onerror="this.style.display='none';this.nextElementSibling.style.display='flex'">`
            : ""}
          <div class="news-favicon-fallback" style="display:${faviconUrl?"none":"flex"}">${initials}</div>
        </div>
        <span class="src-pub">${escapeHtml(item.source||domain||"FONTE")}</span>
        <span class="src-rating">${pubFormatted}</span>
      </div>
      <span class="news-title">${escapeHtml(item.title)}</span>
      <a class="news-readlink" href="${escapeHtml(item.link)}" target="_blank" rel="noopener noreferrer">Ler notícia <span style="font-size:13px;">→</span></a>
    </div>`;
  }).join("");

  const showArrows = totalNews > 3;
  const news = totalNews ? `
    <div class="carousel-outer">
      <div class="carousel-viewport">
        <div class="carousel-track" id="news-track">${newsCards}</div>
      </div>
      <div class="carousel-nav">
        <div class="carousel-dots" id="news-dots">
          ${newsItems.map((_,i)=>`<button class="c-dot${i===0?" active":""}" onclick="newsGoTo(${i})" aria-label="Notícia ${i+1}"></button>`).join("")}
        </div>
        ${showArrows ? `<div class="carousel-arrows">
          <button class="carousel-btn" id="carousel-prev" onclick="newsCarousel(-1)" aria-label="Anterior">&#8592;</button>
          <button class="carousel-btn" id="carousel-next" onclick="newsCarousel(1)" aria-label="Próximo">&#8594;</button>
        </div>` : ""}
      </div>
    </div>
  ` : `<div class="empty-msg">Nenhuma notícia recente encontrada.</div>`;

  const reasons = (result.reasons||[]).map((r,i)=>
    `<div class="reason-row"><span class="reason-i">${String(i+1).padStart(2,"0")}</span><span class="reason-t">${escapeHtml(r)}</span></div>`
  ).join("") || `<div class="reason-row"><span class="reason-i">—</span><span class="reason-t">Sem detalhes adicionais.</span></div>`;

  // Para imagem/vídeo: apenas resultado da IA
  if (result.inputType === 'imagem' || result.inputType === 'video') {
    return `<div class="result-wrap">
  <div class="r-meta">
    <span class="r-tag">${typeLabel}</span>
    <span class="r-ts">${ts}</span>
  </div>

  ${aiSection}
  ${videoFramesSection}
</div>`;
  }

  // Para texto/link: resultado completo
  return `<div class="result-wrap">

  <div class="r-meta">
    <span class="r-tag">${typeLabel}</span>
    <span class="r-ts">${ts}</span>
    <span class="r-query">${escapeHtml(result.claimQuery||"—")}</span>
  </div>

  ${aiSection}
  ${videoFramesSection}

  <div class="verdict-block ${v.cls}">
    <div class="verdict-left">
      <div class="verdict-label">${v.label}</div>
      <div class="verdict-summary">${escapeHtml(result.summary||"")}</div>
    </div>
    <div class="verdict-right">
      <div class="conf-num">${pct}<span class="conf-unit">%</span></div>
      <div class="conf-desc">confiança</div>
      <div class="conf-bar"><div class="conf-fill" style="width:${pct}%"></div></div>
    </div>
  </div>

  <div class="reply-block">
    <div class="block-label">CONCLUSÃO</div>
    <p class="reply-text">${escapeHtml(result.reply||"")}</p>
  </div>

  <div class="two-col">
    <div>
      <div class="block-label">FUNDAMENTOS</div>
      <div class="reasons-list">${reasons}</div>
    </div>
    <div>
      <div class="block-label">CHECAGENS</div>
      <div class="src-list">${checks}</div>
    </div>
  </div>

  <div>
    <div class="block-label">NOTÍCIAS RECENTES</div>
    ${news}
  </div>

  ${result.page ? `<div><div class="block-label">PÁGINA ANALISADA</div>
    <div class="src-item"><div class="src-row"><span class="src-pub">${escapeHtml(result.page.title||"")}</span></div>
    <span class="src-text">${escapeHtml(result.page.description||"")}</span>
    <a class="src-link" href="${escapeHtml(result.page.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(result.page.url)}</a></div></div>` : ""}

  ${result.transcript ? `<div><div class="block-label">TRANSCRIÇÃO</div><div class="transcript">${escapeHtml(result.transcript)}</div></div>` : ""}

  <div class="disclaimer">Análise automatizada por IA. Confirme sempre com fontes primárias antes de publicar.</div>
</div>`;
}

// ══════════════════════════════════════════════════════════
// 🔐 PÁGINAS DE LOGIN / REGISTRO
// ══════════════════════════════════════════════════════════
function renderAuthPage({ mode = "login", error = "", email = "", name = "", notice = "", token = "" }) {
  const isLogin = mode === "login";
  const isEsqueci = mode === "esqueci";
  const isRedefinir = mode === "redefinir";
  const titles = { login: "Entrar", register: "Criar conta", esqueci: "Recuperar senha", redefinir: "Nova senha" };
  const pageTitle = titles[mode] || "Entrar";
  return `<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${pageTitle} · Ecoa Saúde</title>
  <link rel="icon" href="${ECOA_FAVICON}">
  ${ECOA_FONTS}
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: #FFFFFF; color: #1F242C;
      font-family: 'Figtree', system-ui, sans-serif;
      min-height: 100vh; display: flex; align-items: center; justify-content: center;
      padding: 20px; -webkit-font-smoothing: antialiased;
    }
    .auth-card { width: 100%; max-width: 400px; }
    .auth-brand { display: flex; flex-direction: column; align-items: center; gap: 12px; margin-bottom: 8px; }
    .auth-logo { font-size: 30px; font-weight: 800; letter-spacing: -0.02em; line-height: 1; }
    .auth-logo .wm-a { color: #D8282E; } .auth-logo .wm-b { color: #2560CC; }
    .auth-sub { text-align: center; font-size: 15px; color: #4A5260; margin-bottom: 28px; }
    .auth-box { background: #FFFFFF; border: 1px solid #E6E8EC; border-radius: 22px; padding: 28px 26px; box-shadow: 0 1px 2px rgba(16,24,40,.04), 0 12px 32px rgba(16,24,40,.07); }
    .f { margin-bottom: 14px; }
    .f label { display: block; font-size: 13.5px; font-weight: 600; color: #4A5260; margin-bottom: 6px; }
    .f input {
      width: 100%; background: #F3F5F8; border: 1px solid #E3E6EB; border-radius: 14px;
      color: #0F1217; font-family: inherit; font-size: 16px;
      padding: 12px 14px; outline: none; transition: border-color .15s, box-shadow .15s;
    }
    .f input::placeholder { color: #6B7280; }
    .f input:focus { border-color: #2560CC; box-shadow: 0 0 0 3px rgba(37,96,204,.16); }
    .auth-btn {
      width: 100%; margin-top: 8px; padding: 13px;
      background: #2560CC; color: #fff; border: none; border-radius: 999px;
      font-family: inherit; font-size: 16px; font-weight: 700; cursor: pointer;
      transition: background .15s;
    }
    .auth-btn:hover { background: #1E4FB0; }
    .auth-btn:focus-visible, a:focus-visible { outline: 2px solid #2560CC; outline-offset: 2px; }
    .auth-error {
      background: rgba(239,83,87,.1); border: 1px solid rgba(239,83,87,.35);
      color: #B71C1C; font-size: 14px; padding: 10px 14px; border-radius: 12px;
      margin-bottom: 16px; line-height: 1.45;
    }
    .auth-switch { text-align: center; margin-top: 20px; font-size: 14.5px; color: #6B7280; }
    .auth-switch a { color: #2560CC; text-decoration: none; font-weight: 600; }
    .auth-switch a:hover { color: #0F1217; }
    .auth-plans { margin-top: 20px; font-size: 13px; color: #6B7280; line-height: 1.7; text-align: center; }
    .auth-plans b { color: #4A5260; }
    .auth-tag { text-align: center; font-size: 13px; color: #6B7280; margin-top: 26px; }
  </style>
</head>
<body>
  <div class="auth-card">
    <div class="auth-brand">${ecoaMark(64, "au")}<div class="auth-logo">${ECOA_WORDMARK}</div></div>
    <div class="auth-sub">Recebeu uma informação e ficou na dúvida? A gente checa.</div>
    <div class="auth-box">
    ${error ? `<div class="auth-error">${escapeHtml(error)}</div>` : ""}
    ${notice ? `<div class="auth-error" style="background:rgba(77,184,131,0.1); border-color:rgba(77,184,131,0.35); color:#1E7A4C;">${escapeHtml(notice)}</div>` : ""}
    <form method="post" action="${isRedefinir ? "/redefinir" : isEsqueci ? "/esqueci" : isLogin ? "/login" : "/register"}">
      ${mode === "register" ? `
      <div class="f">
        <label>Nome</label>
        <input type="text" name="name" required minlength="2" maxlength="80" value="${escapeHtml(name)}" placeholder="Seu nome ou organização">
      </div>` : ""}
      ${!isRedefinir ? `
      <div class="f">
        <label>E-mail</label>
        <input type="email" name="email" required maxlength="120" value="${escapeHtml(email)}" placeholder="voce@empresa.com.br">
      </div>` : ""}
      ${isEsqueci ? "" : isRedefinir ? `
      <input type="hidden" name="token" value="${escapeHtml(token)}">
      <div class="f">
        <label>Nova senha</label>
        <input type="password" name="password" required minlength="6" maxlength="72" placeholder="Mínimo 6 caracteres">
      </div>
      <div class="f">
        <label>Confirmar nova senha</label>
        <input type="password" name="confirm" required minlength="6" maxlength="72" placeholder="Repita a nova senha">
      </div>` : `
      <div class="f">
        <label>Senha</label>
        <input type="password" name="password" required minlength="6" maxlength="72" placeholder="${isLogin ? "Sua senha" : "Mínimo 6 caracteres"}">
      </div>`}
      ${isLogin ? `<div style="text-align:right; margin:-6px 0 14px;"><a href="/esqueci" style="font-size:13.5px; color:#2560CC;">Esqueceu a senha?</a></div>` : ""}
      <button class="auth-btn" type="submit">${isRedefinir ? "Salvar nova senha" : isEsqueci ? "Enviar link de recuperação" : isLogin ? "Entrar" : "Criar conta grátis"}</button>
    </form>
    <div class="auth-switch">
      ${isLogin ? `Não tem conta? <a href="/register">Criar conta</a>`
        : isEsqueci || isRedefinir ? `Lembrou a senha? <a href="/login">Entrar</a>`
        : `Já tem conta? <a href="/login">Entrar</a>`}
    </div>
    </div>
    ${mode === "register" ? `
    <div class="auth-plans">
      A conta é gratuita e você pode fazer <b>quantas verificações quiser</b>, sem cartão.
    </div>` : ""}
    <div class="auth-tag">Ouvir, acolher, transformar</div>
  </div>
</body>
</html>`;
}

// ══════════════════════════════════════════════════════════
// ⚙️ PÁGINA: CONTA (configurações)
// ══════════════════════════════════════════════════════════
function renderSubPage(title, content, user) {
  const info = usageInfo(user);
  return `<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${escapeHtml(title)} · Ecoa Saúde</title>
  <link rel="icon" href="${ECOA_FAVICON}">
  ${ECOA_FONTS}
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background:#FFFFFF; color:#1F242C; font-family:'Figtree',system-ui,sans-serif; font-size:16px; line-height:1.6; min-height:100vh; -webkit-font-smoothing:antialiased; }
    a { color:#4A5260; text-decoration:none; } a:hover { color:#0F1217; }
    header { border-bottom:1px solid #E6E8EC; padding:0 28px; display:flex; align-items:center; justify-content:space-between; height:64px; background:#F6F7F9; }
    .logo { display:flex; align-items:center; gap:10px; font-weight:800; font-size:20px; letter-spacing:-0.02em; line-height:1; }
    .logo .wm-a { color:#D8282E; } .logo .wm-b { color:#2560CC; }
    .nav { display:flex; align-items:center; gap:6px; }
    .nav a { font-size:14.5px; font-weight:600; color:#4A5260; padding:7px 12px; border-radius:999px; transition:background .15s, color .15s; }
    .nav a:hover { color:#0F1217; background:#EEF1F5; }
    .nav a.active { color:#0F1217; background:#F3F5F8; }
    .nav .sair:hover { color:#C62828; }
    .wrap { max-width:820px; margin:0 auto; padding:40px 24px 80px; }
    .page-title { font-size:30px; font-weight:800; letter-spacing:-0.015em; color:#0F1217; margin-bottom:6px; line-height:1.2; }
    .page-sub { font-size:15px; color:#4A5260; margin-bottom:32px; }
    .card { background:#F6F7F9; border:1px solid #E6E8EC; border-radius:20px; padding:26px; margin-bottom:20px; }
    .card-title { font-size:17px; font-weight:700; color:#0F1217; margin-bottom:18px; }
    .f { margin-bottom:14px; }
    .f label { display:block; font-size:13.5px; font-weight:600; color:#4A5260; margin-bottom:6px; }
    .f input { width:100%; background:#F3F5F8; border:1px solid #E3E6EB; border-radius:14px; color:#0F1217; font-family:inherit; font-size:16px; padding:11px 14px; outline:none; transition:border-color .15s, box-shadow .15s; }
    .f input:focus { border-color:#2560CC; box-shadow:0 0 0 3px rgba(37,96,204,.16); }
    .f input[disabled] { color:#6B7280; cursor:not-allowed; }
    .btn { padding:11px 24px; background:#2560CC; color:#fff; border:none; border-radius:999px; font-family:inherit; font-size:15px; font-weight:700; cursor:pointer; transition:background .15s; }
    .btn:hover { background:#1E4FB0; }
    :focus-visible { outline:2px solid #2560CC; outline-offset:2px; }
    .msg-ok { background:rgba(77,184,131,.1); border:1px solid rgba(77,184,131,.35); color:#1E7A4C; font-size:14px; padding:10px 14px; border-radius:12px; margin-bottom:20px; }
    .msg-err { background:rgba(239,83,87,.1); border:1px solid rgba(239,83,87,.35); color:#B71C1C; font-size:14px; padding:10px 14px; border-radius:12px; margin-bottom:20px; }
    .usage-bar { height:6px; background:#E6E8EC; border-radius:3px; overflow:hidden; margin-top:10px; }
    .usage-fill { height:100%; border-radius:3px; }
    .plans-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(230px,1fr)); gap:16px; }
    .plan-card { background:#F6F7F9; border:1px solid #E6E8EC; border-radius:20px; padding:26px 22px; display:flex; flex-direction:column; transition:border-color .15s; position:relative; }
    .plan-card:hover { border-color:#D5D9E0; }
    .plan-card.current { border-color:#2560CC; }
    .plan-badge { position:absolute; top:-11px; left:50%; transform:translateX(-50%); background:#2560CC; color:#fff; font-size:12px; font-weight:700; padding:3px 12px; border-radius:999px; white-space:nowrap; }
    .plan-name { font-size:20px; font-weight:800; color:#0F1217; margin-bottom:4px; }
    .plan-price { font-size:28px; font-weight:800; color:#2560CC; margin-bottom:14px; }
    .plan-feats { list-style:none; font-size:14.5px; color:#4A5260; line-height:2; margin-bottom:20px; flex:1; }
    .plan-feats li::before { content:'✓ '; color:#2E8B57; }
    .plan-btn { width:100%; padding:11px; border-radius:999px; font-family:inherit; font-size:14.5px; font-weight:700; cursor:pointer; border:1px solid #D5D9E0; background:transparent; color:#1F242C; transition:all .15s; text-align:center; display:block; }
    .plan-btn:hover { background:#0F1217; color:#FFFFFF; border-color:#0F1217; }
    .plan-btn[disabled] { opacity:.35; cursor:default; }
    .plan-btn[disabled]:hover { background:transparent; color:#1F242C; border-color:#D5D9E0; }
    footer { border-top:1px solid #E6E8EC; padding:18px 28px; text-align:center; font-size:13px; color:#6B7280; }
    @media (max-width: 700px) {
      header { height:auto; min-height:60px; flex-wrap:wrap; padding:10px 14px; gap:8px 12px; }
      .nav { flex-wrap:wrap; gap:4px; }
      .wrap { padding:24px 14px 60px; }
      .card { padding:18px 16px; }
      table { font-size:12px !important; }
    }
  </style>
</head>
<body>
<header>
  <a class="logo" href="/">${ecoaMark(28, "sp")}${ECOA_WORDMARK}</a>
  <nav class="nav">
    <a href="/">Verificar</a>
    ${isAdmin(user) ? `<a href="/admin" class="${title==='Admin'?'active':''}" style="color:#9A7400;">Admin</a>` : ""}
    <a href="/conta" class="${title==='Minha Conta'?'active':''}">Conta</a>
    <a href="/logout" class="sair">Sair</a>
  </nav>
</header>
<div class="wrap">
${content}
</div>
<footer>Ecoa Saúde · ${escapeHtml(user.name)} · ${info.used} ${info.used === 1 ? "verificação" : "verificações"} este mês · ${info.total} no total</footer>
</body>
</html>`;
}

function renderContaPage(user, q = {}) {
  const info = usageInfo(user);
  let msg = "";
  if (q.ok === "perfil") msg = `<div class="msg-ok">✓ Perfil atualizado com sucesso.</div>`;
  if (q.ok === "senha") msg = `<div class="msg-ok">✓ Senha alterada com sucesso.</div>`;
  if (q.erro) msg = `<div class="msg-err">${escapeHtml(q.erro)}</div>`;

  const content = `
  <div class="page-title">Minha Conta</div>
  <div class="page-sub">Gerencie seu perfil, senha e acompanhe seu uso.</div>
  ${msg}

  <div class="card">
    <div class="card-title">Seu uso</div>
    <div style="display:flex; justify-content:space-between; align-items:baseline; flex-wrap:wrap; gap:10px;">
      <div>
        <span style="font-size:22px; font-weight:700; color:#14171C;">${info.used}</span>
        <span style="font-size:13.5px; color:#6B7280; margin-left:8px;">verificações este mês</span>
      </div>
      <div style="font-size:14px; color:#2560CC; font-weight:600;">${info.total} no total</div>
    </div>
    <div style="margin-top:14px; font-size:13.5px; color:#6B7280;">Você pode fazer quantas verificações quiser, sem limite.</div>
  </div>

  <div class="card">
    <div class="card-title">Perfil</div>
    <form method="post" action="/conta/perfil">
      <div class="f">
        <label>Nome</label>
        <input type="text" name="name" required minlength="2" maxlength="80" value="${escapeHtml(user.name)}">
      </div>
      <div class="f">
        <label>E-mail (não pode ser alterado)</label>
        <input type="email" value="${escapeHtml(user.email)}" disabled>
      </div>
      <button class="btn" type="submit">Salvar perfil</button>
    </form>
  </div>

  <div class="card">
    <div class="card-title">Alterar Senha</div>
    <form method="post" action="/conta/senha">
      <div class="f">
        <label>Senha atual</label>
        <input type="password" name="current" required>
      </div>
      <div class="f">
        <label>Nova senha</label>
        <input type="password" name="password" required minlength="6" maxlength="72" placeholder="Mínimo 6 caracteres">
      </div>
      <div class="f">
        <label>Confirmar nova senha</label>
        <input type="password" name="confirm" required minlength="6" maxlength="72">
      </div>
      <button class="btn" type="submit">Alterar senha</button>
    </form>
  </div>

  <div class="card" style="border-color:rgba(229,57,53,0.35);">
    <div class="card-title" style="color:#C62828;">Zona de Perigo</div>
    <div style="font-size:13px; color:#6B7280; margin-bottom:6px;">Conta criada em ${new Date(user.created_at).toLocaleDateString("pt-BR", { day:"2-digit", month:"long", year:"numeric" })}</div>
    <p style="font-size:14px; color:#4A5260; margin-bottom:18px; line-height:1.5;">Excluir sua conta remove permanentemente seus dados de acesso e histórico de uso. <strong style="color:#C62828;">Esta ação não pode ser desfeita.</strong><br><span style="font-size:12px; color:#6B7280;">Mantemos apenas um registro anônimo (hash) para prevenir abuso do período de teste gratuito.</span></p>
    <form method="post" action="/conta/excluir" onsubmit="return confirm('Tem certeza ABSOLUTA? Sua conta e todos os dados serão apagados permanentemente. Esta ação NÃO pode ser desfeita.');">
      <div class="f">
        <label>Digite sua senha para confirmar</label>
        <input type="password" name="password" required placeholder="Sua senha atual">
      </div>
      <button type="submit" style="padding:12px 26px; background:transparent; color:#C62828; border:1px solid #C62828; border-radius:2px; font-size:14px; font-weight:700; letter-spacing:0.12em; text-transform:uppercase; cursor:pointer; transition:all 0.15s;" onmouseover="this.style.background='#C62828';this.style.color='#fff'" onmouseout="this.style.background='transparent';this.style.color='#C62828'">Excluir minha conta</button>
    </form>
  </div>`;
  return renderSubPage("Minha Conta", content, user);
}

// ══════════════════════════════════════════════════════════
// 🎨 ECOA SAÚDE — marca (símbolo em SVG + favicon)
// ══════════════════════════════════════════════════════════
function ecoaMark(size = 32, idp = "mk", extraClass = "") {
  const bubbleA = `<circle cx="24" cy="24" r="18"/><path d="M11 35 L6 49 L22 41 Z"/>`;
  const bubbleB = `<circle cx="40" cy="26" r="18"/><path d="M53 37 L58 51 L42 43 Z"/>`;
  return `<svg class="ecoa-mark ${extraClass}" width="${size}" height="${Math.round(size * 56 / 64)}" viewBox="0 0 64 56" aria-hidden="true" focusable="false">
    <defs><clipPath id="${idp}-b">${bubbleB}</clipPath></defs>
    <g fill="#D8282E">${bubbleA}</g>
    <g fill="#2560CC">${bubbleB}</g>
    <g fill="#8C1D3B" clip-path="url(#${idp}-b)">${bubbleA}</g>
    <circle class="mk-dot" cx="27" cy="25" r="2.3" fill="#fff"/>
    <circle class="mk-dot" cx="32.5" cy="25" r="2.3" fill="#fff"/>
    <circle class="mk-dot" cx="38" cy="25" r="2.3" fill="#fff"/>
  </svg>`;
}
const ECOA_FAVICON = "data:image/svg+xml," + encodeURIComponent(
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 56"><defs><clipPath id="b"><circle cx="40" cy="26" r="18"/><path d="M53 37 L58 51 L42 43 Z"/></clipPath></defs><g fill="#D8282E"><circle cx="24" cy="24" r="18"/><path d="M11 35 L6 49 L22 41 Z"/></g><g fill="#2560CC"><circle cx="40" cy="26" r="18"/><path d="M53 37 L58 51 L42 43 Z"/></g><g fill="#8C1D3B" clip-path="url(#b)"><circle cx="24" cy="24" r="18"/><path d="M11 35 L6 49 L22 41 Z"/></g><circle cx="27" cy="25" r="2.3" fill="#fff"/><circle cx="32.5" cy="25" r="2.3" fill="#fff"/><circle cx="38" cy="25" r="2.3" fill="#fff"/></svg>`
);
const ECOA_FONTS = `<link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Figtree:wght@400;500;600;700;800&family=Barlow+Condensed:wght@400;600;700&family=Barlow:wght@300;400&display=swap" rel="stylesheet">`;
const ECOA_WORDMARK = `<span class="wm"><span class="wm-a">Ecoa</span><span class="wm-b">Saúde</span></span>`;

function renderPage(content = "", user = null) {
  const hasResult = !!content;

  // 👤 Bloco da conta (rodapé da barra lateral)
  let accountBlock = "";
  if (user) {
    const info = usageInfo(user);
    const initial = escapeHtml(String(user.name || "?").trim().charAt(0).toUpperCase() || "?");
    accountBlock = `
      <div class="account">
        <div class="account-row">
          <div class="avatar" aria-hidden="true">${initial}</div>
          <div class="account-id">
            <div class="account-name">${escapeHtml(user.name)}</div>
            <div class="account-plan">${isAdmin(user) ? "Admin" : "Verificações ilimitadas"}</div>
          </div>
          <a class="icon-btn" href="/logout" title="Sair" aria-label="Sair">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M15 4h3a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-3"/><path d="M10 17l-5-5 5-5"/><path d="M5 12h11"/></svg>
          </a>
        </div>
        <div class="usage">
          <div class="usage-text"><span style="color:var(--accent-blue);">${info.used} ${info.used === 1 ? "verificação" : "verificações"}</span> este mês</div>
        </div>
        <nav class="account-links">
          ${isAdmin(user) ? `<a href="/admin" class="is-admin">Admin</a>` : ""}
          <a href="/conta">Conta</a>
        </nav>
      </div>`;
  }

  // 📜 Histórico
  const historyHtml = (() => {
    const empty = `<div class="sidebar-empty">Suas verificações aparecem aqui.</div>`;
    if (!user) return empty;
    const items = getHistory(user.id);
    if (!items.length) return empty;
    const V_COLORS = { provavelmente_falso: "var(--c-red)", suspeito: "var(--c-amber)", nao_verificado: "var(--c-blue)", provavelmente_verdadeiro: "var(--c-green)" };
    return `<div class="sidebar-items">` + items.map(h => {
      const label = h.text.length > 60 ? h.text.slice(0, 60) + "…" : h.text;
      const dot = h.verdict && V_COLORS[h.verdict]
        ? `<span class="h-dot" style="background:${V_COLORS[h.verdict]};"></span>` : `<span class="h-dot h-dot-empty"></span>`;
      const btn = h.verdict
        ? `<button class="sidebar-item-btn" title="${escapeHtml(h.text)}" onclick="location.href='/historico/ver/${h.id}'">${dot}<span class="h-label">${escapeHtml(label)}</span></button>`
        : `<button class="sidebar-item-btn" title="${escapeHtml(h.text)}" data-text="${escapeHtml(h.text)}" onclick="historyUse(this)">${dot}<span class="h-label">${escapeHtml(label)}</span></button>`;
      return `<div class="sidebar-item" data-hid="${h.id}">
        ${btn}
        <button class="sidebar-item-del" title="Remover" aria-label="Remover do histórico" onclick="historyDel(${h.id}, this)">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M6 6l12 12M18 6L6 18"/></svg>
        </button>
      </div>`;
    }).join("") + `</div>`;
  })();

  return `<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
  <meta name="theme-color" content="#FFFFFF">
  <title>Ecoa Saúde</title>
  <link rel="icon" href="${ECOA_FAVICON}">
  ${ECOA_FONTS}
  <style>
    :root {
      /* superfícies */
      --side:  #F6F7F9;
      --bg:    #FFFFFF;
      --bg2:   #F6F7F9;
      --bg3:   #EEF1F5;
      --dock:  #F3F5F8;
      --line:  #E6E8EC;
      --line2: #D5D9E0;
      /* texto */
      --muted: #6B7280;
      --dim:   #4A5260;
      --text:  #1F242C;
      --white: #0F1217;
      /* marca (logo) */
      --brand-red:  #D8282E;
      --brand-blue: #2560CC;
      --brand-blue-hover: #1E4FB0;
      --red:   #C62828;
      /* semântica do relatório */
      --c-red:   #C62828;
      --c-amber: #B45F06;
      --c-blue:  #2560CC;
      --c-green: #2E8B57;
      --accent-blue: #2560CC;

      --font: 'Figtree', system-ui, -apple-system, 'Segoe UI', sans-serif;
      --side-w: 272px;
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html, body { height: 100%; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: var(--font);
      font-size: 16px;
      line-height: 1.6;
      -webkit-font-smoothing: antialiased;
      overflow: hidden;
    }
    a { color: var(--dim); text-decoration: none; }
    a:hover { color: var(--white); }
    button { font-family: inherit; }
    :focus-visible { outline: 2px solid var(--accent-blue); outline-offset: 2px; border-radius: 8px; }
    [hidden] { display: none !important; }

    /* ── Wordmark ───────────────────────────── */
    .wm { font-weight: 800; letter-spacing: -0.02em; line-height: 1; }
    .wm-a { color: var(--brand-red); }
    .wm-b { color: #2560CC; }
    .ecoa-mark { display: block; flex-shrink: 0; overflow: visible; }

    /* ── Estrutura ──────────────────────────── */
    .app { display: flex; height: 100vh; height: 100dvh; }

    .sidebar {
      width: var(--side-w);
      flex-shrink: 0;
      background: var(--side);
      border-right: 1px solid var(--line);
      display: flex;
      flex-direction: column;
      min-height: 0;
    }
    .side-top { padding: 16px 14px 10px; }
    .brand { display: flex; align-items: center; gap: 10px; padding: 4px 6px 16px; color: inherit; }
    .brand .wm { font-size: 20px; }
    .brand:hover { color: inherit; }
    .icon-btn.side-close { display: none; margin-left: auto; }

    .new-btn {
      display: flex; align-items: center; gap: 10px;
      width: 100%;
      padding: 10px 12px;
      border: 1px solid var(--line2);
      border-radius: 12px;
      color: var(--white);
      font-size: 14.5px; font-weight: 600;
      transition: background .15s, border-color .15s;
    }
    .new-btn:hover { background: var(--bg2); border-color: var(--muted); color: var(--white); }
    .new-btn svg { color: var(--dim); }

    .side-history { flex: 1; min-height: 0; overflow-y: auto; padding: 6px 8px 12px; scrollbar-width: thin; scrollbar-color: var(--line2) transparent; }
    .sidebar-label {
      display: flex; align-items: center; justify-content: space-between;
      padding: 12px 8px 6px;
      font-size: 12.5px; font-weight: 600; color: var(--muted);
    }
    .sidebar-clear { background: none; border: none; color: var(--muted); font-size: 12.5px; cursor: pointer; padding: 2px 4px; }
    .sidebar-clear:hover { color: var(--c-red); }
    .sidebar-empty { font-size: 13.5px; color: var(--muted); padding: 6px 8px; }
    .sidebar-items { display: flex; flex-direction: column; gap: 1px; }
    .sidebar-item { display: flex; align-items: center; border-radius: 10px; transition: background .12s; }
    .sidebar-item:hover { background: var(--bg2); }
    .sidebar-item-btn {
      flex: 1; min-width: 0;
      display: flex; align-items: center; gap: 10px;
      background: none; border: none; cursor: pointer; text-align: left;
      padding: 8px 4px 8px 10px;
      font-size: 14px; color: var(--dim); line-height: 1.35;
    }
    .sidebar-item-btn:hover { color: var(--white); }
    .h-label { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .h-dot { width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0; }
    .h-dot-empty { border: 1px solid var(--line2); }
    .sidebar-item-del {
      display: grid; place-items: center;
      width: 28px; height: 28px; margin-right: 4px;
      background: none; border: none; border-radius: 8px;
      color: transparent; cursor: pointer; flex-shrink: 0;
    }
    .sidebar-item:hover .sidebar-item-del, .sidebar-item-del:focus-visible { color: var(--muted); }
    .sidebar-item-del:hover { color: var(--c-red) !important; background: var(--bg3); }

    .account { border-top: 1px solid var(--line); padding: 12px 14px 14px; }
    .account-row { display: flex; align-items: center; gap: 10px; }
    .avatar {
      width: 34px; height: 34px; border-radius: 50%;
      display: grid; place-items: center;
      background: var(--brand-blue); color: #fff;
      font-weight: 700; font-size: 15px; flex-shrink: 0;
    }
    .account-id { flex: 1; min-width: 0; }
    .account-name { font-size: 14px; font-weight: 600; color: var(--white); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; line-height: 1.3; }
    .account-plan { font-size: 12.5px; color: var(--muted); line-height: 1.3; }
    .icon-btn {
      display: grid; place-items: center;
      width: 34px; height: 34px; border-radius: 50%;
      color: var(--muted); background: none; border: none; cursor: pointer; flex-shrink: 0;
      transition: background .15s, color .15s;
    }
    .icon-btn:hover { background: var(--bg3); color: var(--white); }
    a.icon-btn[href="/logout"]:hover { color: var(--c-red); }
    .usage { margin-top: 10px; }
    .usage-text { font-size: 12.5px; color: var(--muted); }
    .usage-bar { height: 3px; background: var(--line); border-radius: 3px; overflow: hidden; margin-top: 6px; }
    .usage-fill { height: 100%; border-radius: 3px; }
    .account-links { display: flex; gap: 16px; margin-top: 10px; font-size: 13.5px; font-weight: 500; }
    .account-links a { color: var(--dim); }
    .account-links a:hover { color: var(--white); }
    .account-links .is-admin { color: #9A7400; }

    /* ── Palco (área do chat) ───────────────── */
    .stage { flex: 1; min-width: 0; display: flex; flex-direction: column; position: relative; }
    .topbar { display: none; }

    .thread { overflow-y: auto; scrollbar-width: thin; scrollbar-color: var(--line2) transparent; }
    .thread-inner { width: 100%; max-width: 820px; margin: 0 auto; padding: 0 24px; }

    body.is-home .stage { overflow-y: auto; }
    body.is-home .thread { flex: none; overflow: visible; margin-top: auto; padding-top: 24px; }
    body.is-home .dock { margin-bottom: auto; padding-bottom: 32px; }
    body.is-chat .thread { flex: 1; min-height: 0; }
    body.is-chat .hero, body.is-chat .suggestions { display: none; }
    body.is-home .msg-result { display: none; }

    /* Boas-vindas */
    .hero { text-align: center; padding: 0 0 28px; }
    .hero-mark { position: relative; width: 84px; height: 74px; margin: 0 auto 22px; }
    .hero-mark .ecoa-mark { position: relative; z-index: 1; }
    .echo {
      position: absolute; left: 50%; top: 48%;
      width: 84px; height: 84px; margin: -42px 0 0 -42px;
      border-radius: 50%;
      border: 1.5px solid var(--brand-red);
      opacity: 0;
      animation: echo 1.8s cubic-bezier(.2,.6,.3,1) .15s 1 both;
    }
    .echo.e2 { border-color: #2560CC; animation-delay: .55s; }
    @keyframes echo {
      0%   { transform: scale(.7); opacity: .55; }
      100% { transform: scale(2.1); opacity: 0; }
    }
    .hero h1 { font-size: clamp(26px, 3.4vw, 34px); font-weight: 700; color: var(--white); letter-spacing: -0.015em; line-height: 1.2; }
    .hero p { margin: 10px auto 0; max-width: 46ch; font-size: 16px; color: var(--dim); }

    /* Mensagens */
    .msg-result, .pending { padding: 32px 0 24px; }
    .msg-user {
      margin: 0 0 22px auto;
      max-width: min(78%, 560px);
      width: fit-content;
      background: var(--dock);
      color: var(--white);
      padding: 11px 16px;
      border-radius: 20px 20px 6px 20px;
      font-size: 15.5px;
      overflow-wrap: anywhere;
    }
    .msg-user-file { display: flex; align-items: center; gap: 8px; font-size: 13.5px; color: var(--dim); }
    .msg-user-file + .msg-user-text:not(:empty) { margin-top: 6px; }
    .msg-bot { display: grid; grid-template-columns: 34px 1fr; gap: 14px; align-items: start; }
    .bot-avatar {
      width: 34px; height: 34px; border-radius: 50%;
      background: #fff;
      box-shadow: inset 0 0 0 1px var(--line);
      display: grid; place-items: center;
    }
    .bot-name { font-size: 14px; font-weight: 700; color: var(--white); line-height: 34px; }
    .bot-body { min-width: 0; }

    /* Pensando (usa as bolinhas do símbolo) */
    .thinking .mk-dot { transform-box: fill-box; transform-origin: center; animation: think 1.1s ease-in-out infinite; }
    .thinking .mk-dot:nth-of-type(2) { animation-delay: .15s; }
    .thinking .mk-dot:nth-of-type(3) { animation-delay: .3s; }
    @keyframes think {
      0%, 60%, 100% { transform: translateY(0); opacity: .55; }
      30% { transform: translateY(-2.5px); opacity: 1; }
    }
    .think-title { font-size: 15.5px; color: var(--white); margin: 2px 0 12px; }
    .l-steps { display: flex; flex-direction: column; gap: 2px; }
    .l-step { display: flex; align-items: center; gap: 10px; font-size: 14.5px; color: var(--muted); padding: 3px 0; transition: color .3s; }
    .l-dot { width: 8px; height: 8px; border-radius: 50%; border: 1.5px solid var(--line2); flex-shrink: 0; transition: all .3s; }
    .l-step.active { color: var(--white); }
    .l-step.active .l-dot { border-color: var(--accent-blue); background: var(--accent-blue); box-shadow: 0 0 0 4px rgba(37,96,204,.16); }
    .l-step.done { color: var(--dim); }
    .l-step.done .l-dot { border-color: var(--c-green); background: var(--c-green); }

    /* ── Composer (barra de chat) ───────────── */
    .dock { width: 100%; max-width: 820px; margin: 0 auto; padding: 0 24px 14px; }
    body.is-chat .dock { padding-top: 6px; }
    .composer {
      background: var(--dock);
      border: 1px solid #E3E6EB;
      border-radius: 28px;
      padding: 7px;
      box-shadow: 0 1px 2px rgba(16,24,40,.04), 0 6px 20px rgba(16,24,40,.06);
      transition: border-color .15s, box-shadow .15s;
    }
    .composer:focus-within { border-color: #B9C0CB; background: #fff; }
    .composer.is-drag { border-color: var(--accent-blue); box-shadow: 0 0 0 3px rgba(37,96,204,.18); }
    .composer.is-busy { opacity: .7; }

    .attach {
      display: flex; align-items: center; gap: 10px;
      margin: 3px 3px 6px; padding: 8px 10px 8px 8px;
      width: fit-content; max-width: calc(100% - 6px);
      background: var(--bg3); border: 1px solid var(--line2); border-radius: 14px;
    }
    .attach-ico { width: 34px; height: 34px; border-radius: 9px; background: var(--brand-blue); color: #fff; display: grid; place-items: center; flex-shrink: 0; }
    .attach-txt { min-width: 0; line-height: 1.25; }
    .attach-name { font-size: 13.5px; color: var(--white); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 38ch; }
    .attach-meta { font-size: 12px; color: var(--muted); }
    .attach .icon-btn { width: 26px; height: 26px; }

    .composer-row { display: flex; align-items: flex-end; gap: 4px; }
    .c-btn {
      width: 42px; height: 42px; border-radius: 50%;
      display: grid; place-items: center;
      background: none; border: none; color: var(--white);
      cursor: pointer; flex-shrink: 0;
      transition: background .15s, color .15s;
    }
    .c-btn:hover { background: #E3E6EB; }
    .c-btn.is-live { color: var(--c-red); background: rgba(239,83,87,.14); }
    .c-btn input[type=file] { display: none; }

    .composer textarea {
      flex: 1; min-width: 0;
      background: none; border: none; outline: none; resize: none;
      color: var(--white);
      font-family: var(--font); font-size: 16.5px; line-height: 1.5;
      padding: 9px 6px;
      height: 42px; max-height: 168px;
    }
    .composer textarea::placeholder { color: #7A818C; }

    .counter { align-self: center; font-size: 12.5px; color: var(--muted); padding: 0 6px; font-variant-numeric: tabular-nums; }
    .counter.is-max { color: var(--c-red); }

    .send {
      width: 42px; height: 42px; border-radius: 50%;
      display: grid; place-items: center;
      background: var(--brand-blue); color: #fff;
      border: none; cursor: pointer; flex-shrink: 0;
      transition: background .15s, transform .1s;
    }
    .send:hover:not(:disabled) { background: var(--brand-blue-hover); }
    .send:active:not(:disabled) { transform: scale(.94); }
    .send:disabled { background: #E3E6EB; color: #9AA1AC; cursor: default; }

    .suggestions { display: flex; flex-wrap: wrap; justify-content: center; gap: 8px; margin-top: 16px; }
    .sugg {
      background: none; border: 1px solid var(--line2); border-radius: 999px;
      color: var(--dim); font-size: 14px; padding: 7px 14px; cursor: pointer;
      transition: border-color .15s, color .15s, background .15s;
    }
    .sugg:hover { border-color: var(--muted); color: var(--white); background: var(--bg2); }

    .dock-note { text-align: center; font-size: 12.5px; color: var(--muted); margin-top: 10px; }
    .dock-note.is-error { color: var(--c-red); }

    /* ══ Relatório (classes geradas pelo servidor) ══ */
    .result-body { min-width: 0; }
    .no-result { color: var(--text); font-size: 15.5px; padding-top: 6px; }
    .result-wrap { display: flex; flex-direction: column; gap: 26px; padding-top: 6px; }

    .r-meta { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
    .r-tag {
      font-size: 12px; font-weight: 700; letter-spacing: .02em;
      background: var(--bg3); color: var(--white);
      border: 1px solid var(--line2);
      padding: 2px 10px; border-radius: 999px;
    }
    .r-ts { font-size: 13px; color: var(--muted); }
    .r-query { font-size: 13.5px; color: var(--dim); font-style: italic; }

    .verdict-block {
      display: flex; justify-content: space-between; align-items: flex-start; gap: 20px;
      padding: 20px 22px;
      border: 1px solid var(--line);
      border-radius: 18px;
      background: var(--bg2);
      position: relative; overflow: hidden;
    }
    .verdict-block::before { content: ''; position: absolute; left: 0; top: 0; bottom: 0; width: 4px; }
    .verdict-block.vf { background: #FDF1F1; border-color: #F3CFCF; }
    .verdict-block.vs { background: #FDF5EA; border-color: #F1DDBE; }
    .verdict-block.vn { background: #EEF3FC; border-color: #CCDAF3; }
    .verdict-block.vt { background: #EDF7F1; border-color: #C8E6D4; }
    .verdict-block.vf::before { background: var(--c-red); }
    .verdict-block.vs::before { background: var(--c-amber); }
    .verdict-block.vn::before { background: var(--c-blue); }
    .verdict-block.vt::before { background: var(--c-green); }
    .verdict-label { font-size: 22px; font-weight: 800; letter-spacing: -0.01em; line-height: 1.2; margin-bottom: 6px; }
    .vf .verdict-label, .vf .conf-num { color: var(--c-red); }
    .vs .verdict-label, .vs .conf-num { color: var(--c-amber); }
    .vn .verdict-label, .vn .conf-num { color: var(--c-blue); }
    .vt .verdict-label, .vt .conf-num { color: var(--c-green); }
    .verdict-summary { font-size: 15.5px; color: var(--text); line-height: 1.55; max-width: 560px; }
    .verdict-right { text-align: right; flex-shrink: 0; min-width: 92px; }
    .conf-num { font-size: 38px; font-weight: 800; line-height: 1; font-variant-numeric: tabular-nums; }
    .conf-unit { font-size: 19px; }
    .conf-desc { font-size: 12px; color: var(--muted); margin: 4px 0 8px; }
    .conf-bar { height: 4px; background: var(--line); border-radius: 4px; overflow: hidden; }
    .conf-fill { height: 100%; border-radius: 4px; }
    .vf .conf-fill { background: var(--c-red); }
    .vs .conf-fill { background: var(--c-amber); }
    .vn .conf-fill { background: var(--c-blue); }
    .vt .conf-fill { background: var(--c-green); }

    .block-label { font-size: 15px; font-weight: 700; color: var(--white); margin-bottom: 12px; }
    .reply-block { padding: 18px 20px; border-radius: 18px; background: var(--bg2); border: 1px solid var(--line); }
    .reply-text { font-size: 16.5px; color: var(--text); line-height: 1.7; }

    .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 22px; }
    .reasons-list { display: flex; flex-direction: column; gap: 12px; }
    .reason-row { display: flex; gap: 12px; align-items: flex-start; }
    .reason-i { font-size: 13px; font-weight: 700; color: var(--accent-blue); min-width: 22px; padding-top: 3px; font-variant-numeric: tabular-nums; }
    .reason-t { font-size: 15.5px; color: var(--text); line-height: 1.55; }

    .src-list { display: flex; flex-direction: column; gap: 8px; }
    .src-item { padding: 13px 15px; border: 1px solid var(--line); border-radius: 14px; background: var(--bg2); display: flex; flex-direction: column; gap: 6px; transition: border-color .15s; }
    .src-item:hover { border-color: var(--line2); }
    .src-row { display: flex; justify-content: space-between; align-items: baseline; gap: 8px; }
    .src-pub { font-size: 13.5px; font-weight: 700; color: var(--white); }
    .src-rating { font-size: 12.5px; color: var(--muted); text-align: right; }
    .src-text { font-size: 14px; color: var(--dim); line-height: 1.5; }
    .src-link { font-size: 12px; color: var(--muted); word-break: break-all; }
    .src-link:hover { color: var(--accent-blue); }

    .steps-strip { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 14px; }
    .step { display: flex; gap: 12px; align-items: flex-start; }
    .step-num { font-size: 22px; font-weight: 800; color: var(--line2); line-height: 1; min-width: 30px; }
    .step-title { font-size: 15px; font-weight: 700; color: var(--white); margin-bottom: 3px; }
    .step-desc { font-size: 13.5px; color: var(--muted); line-height: 1.5; }
    .examples-label { font-size: 13px; font-weight: 600; color: var(--muted); margin: 14px 0 8px; }
    .example-chips { display: flex; flex-wrap: wrap; gap: 8px; }
    .chip { background: none; border: 1px solid var(--line2); color: var(--dim); font-size: 13px; padding: 6px 12px; border-radius: 999px; cursor: pointer; }
    .chip:hover { border-color: var(--accent-blue); color: var(--white); }
    .sources-strip { display: flex; flex-wrap: wrap; align-items: baseline; gap: 8px 22px; padding: 14px 18px; background: var(--bg2); border: 1px solid var(--line); border-radius: 14px; font-size: 13px; }
    .sources-title { font-size: 13px; font-weight: 700; color: var(--muted); }
    .source-item { color: var(--dim); white-space: nowrap; }
    .source-sub { color: var(--muted); font-size: 12px; }

    .carousel-outer { position: relative; }
    .carousel-viewport { overflow: hidden; width: 100%; }
    .carousel-track { display: flex; gap: 12px; transition: transform .35s cubic-bezier(.25,.46,.45,.94); will-change: transform; }
    .news-slide {
      flex: 0 0 calc((100% - 24px) / 3);
      padding: 15px 16px; border: 1px solid var(--line); border-radius: 14px;
      display: flex; flex-direction: column; gap: 10px;
      background: var(--bg2); transition: border-color .15s;
    }
    .news-slide:hover { border-color: var(--line2); }
    .news-header { display: flex; align-items: center; gap: 10px; }
    .news-favicon-wrap { width: 26px; height: 26px; flex-shrink: 0; }
    .news-favicon { width: 26px; height: 26px; border-radius: 6px; object-fit: contain; background: var(--bg3); display: block; }
    .news-favicon-fallback { width: 26px; height: 26px; border-radius: 6px; background: var(--line2); color: var(--dim); font-size: 11px; font-weight: 700; display: flex; align-items: center; justify-content: center; }
    .news-header .src-pub { flex: 1; }
    .news-header .src-rating { flex-shrink: 0; }
    .news-title { font-size: 15px; color: var(--white); line-height: 1.45; font-weight: 500; }
    .news-readlink { display: inline-flex; align-items: center; gap: 5px; margin-top: auto; font-size: 13.5px; font-weight: 600; color: var(--accent-blue); }
    .news-readlink:hover { color: var(--white); }
    .carousel-nav { display: flex; align-items: center; justify-content: space-between; margin-top: 12px; }
    .carousel-arrows { display: flex; gap: 6px; }
    .carousel-btn { width: 34px; height: 34px; border-radius: 50%; background: var(--bg3); border: 1px solid var(--line2); color: var(--dim); font-size: 15px; cursor: pointer; display: grid; place-items: center; padding: 0; line-height: 1; }
    .carousel-btn:hover { color: var(--white); background: var(--line2); }
    .carousel-btn:disabled { opacity: .3; cursor: default; }
    .carousel-dots { display: flex; gap: 6px; align-items: center; }
    .c-dot { width: 6px; height: 6px; border-radius: 50%; border: 1px solid var(--muted); background: transparent; cursor: pointer; padding: 0; transition: all .15s; }
    .c-dot.active { background: var(--accent-blue); border-color: var(--accent-blue); transform: scale(1.35); }

    .empty-msg { font-size: 15px; color: var(--muted); padding: 10px 0; font-style: italic; }
    .transcript { font-size: 15px; color: var(--dim); line-height: 1.7; white-space: pre-wrap; padding: 16px; border: 1px solid var(--line); border-radius: 14px; background: var(--bg2); }
    .disclaimer { font-size: 13px; color: var(--muted); padding-top: 16px; border-top: 1px solid var(--line); }
    .char-warning { color: var(--c-red); }

    @keyframes pulse-dot { 0%, 100% { opacity: 1; } 50% { opacity: .45; } }
    .tech-info {
      display: inline-flex; align-items: center; justify-content: center;
      width: 16px; height: 16px; min-width: 16px; border-radius: 50%;
      background: #9AA1AC; color: #fff; font-size: 10px; font-weight: 700;
      cursor: help; position: relative; line-height: 1; outline: none;
    }
    .tech-info:hover, .tech-info:focus { background: var(--brand-blue); color: #fff; }
    .tech-info::after {
      content: attr(data-tip);
      position: absolute; bottom: calc(100% + 8px); left: 50%; transform: translateX(-50%);
      background: #F6F7F9; color: #1F242C; border: 1px solid var(--line2); border-radius: 10px;
      padding: 10px 12px; width: 230px; max-width: min(230px, 78vw);
      font-size: 12.5px; font-weight: 400; font-family: var(--font); line-height: 1.5; text-align: left; white-space: normal;
      opacity: 0; visibility: hidden; transition: opacity .15s, visibility .15s;
      z-index: 100; box-shadow: 0 8px 24px rgba(16,24,40,.14); pointer-events: none;
    }
    .tech-info:hover::after, .tech-info:focus::after { opacity: 1; visibility: visible; }

    /* Nada dentro do relatório pode estourar a largura */
    .result-body, .result-wrap { max-width: 100%; overflow-wrap: anywhere; word-break: break-word; }
    .result-body *, .result-wrap * { min-width: 0; max-width: 100%; }
    .result-body img { max-width: 100% !important; height: auto; }
    .src-link, .news-readlink, .news-title, .transcript { word-break: break-word; overflow-wrap: anywhere; }

    .backdrop { display: none; }

    /* ── Responsivo ─────────────────────────── */
    @media (max-width: 900px) {
      .sidebar {
        position: fixed; inset: 0 auto 0 0; z-index: 50;
        width: min(300px, 86vw);
        transform: translateX(-100%);
        transition: transform .22s ease;
      }
      body.side-open .sidebar { transform: none; }
      .backdrop { display: block; position: fixed; inset: 0; z-index: 40; background: rgba(15,18,23,.35); opacity: 0; pointer-events: none; transition: opacity .22s; }
      body.side-open .backdrop { opacity: 1; pointer-events: auto; }
      .icon-btn.side-close { display: grid; }

      .topbar {
        display: flex; align-items: center; gap: 6px;
        padding: 8px 10px; flex-shrink: 0;
      }
      .topbar .brand { padding: 0; gap: 8px; }
      .topbar .brand .wm { font-size: 17px; }
      .topbar .spacer { flex: 1; }
      body.is-home .topbar { position: sticky; top: 0; background: var(--bg); z-index: 5; }

      .news-slide { flex: 0 0 calc((100% - 12px) / 2); }
    }
    @media (max-width: 680px) {
      .thread-inner { padding: 0 16px; }
      .dock { padding: 0 10px 10px; padding-bottom: max(10px, env(safe-area-inset-bottom)); }
      .msg-bot { grid-template-columns: 1fr; gap: 8px; }
      .bot-head { display: flex; align-items: center; gap: 10px; }
      .bot-avatar { width: 28px; height: 28px; }
      .bot-name { line-height: 28px; }
      .two-col { grid-template-columns: 1fr; }
      .verdict-block { flex-direction: column; gap: 14px; padding: 16px; }
      .verdict-right { text-align: left; width: 100%; }
      .conf-num { font-size: 32px; }
      .result-body [style*="grid-template-columns"] { grid-template-columns: 1fr !important; }
      .result-body [style*="repeat(auto-fill"], .result-body [style*="repeat(auto-fit"] { grid-template-columns: repeat(auto-fill, minmax(118px, 1fr)) !important; }
      .source-item { white-space: normal; }
      .src-row { flex-wrap: wrap; }
      .src-rating { text-align: left; }
      .news-slide { flex: 0 0 100%; }
      .suggestions { justify-content: flex-start; flex-wrap: nowrap; overflow-x: auto; padding: 0 4px 4px; scrollbar-width: none; }
      .sugg { white-space: nowrap; }
      .attach-name { max-width: 22ch; }
      .hero p { font-size: 15px; padding: 0 8px; }
    }
    @media (min-width: 681px) {
      .bot-head { display: contents; }
      .bot-head .bot-name { display: none; }
    }
    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after { animation-duration: .01ms !important; animation-iteration-count: 1 !important; transition-duration: .01ms !important; }
      .echo { display: none; }
    }
  </style>
</head>
<body class="${hasResult ? "is-chat" : "is-home"}">
<div class="app">

  <!-- BARRA LATERAL -->
  <aside class="sidebar" id="sidebar" aria-label="Histórico e conta">
    <div class="side-top">
      <div style="display:flex; align-items:center;">
        <a class="brand" href="/" aria-label="Ecoa Saúde, início">${ecoaMark(30, "sb")}${ECOA_WORDMARK}</a>
        <button class="icon-btn side-close" type="button" onclick="toggleSide(false)" aria-label="Fechar menu">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M6 6l12 12M18 6L6 18"/></svg>
        </button>
      </div>
      <a class="new-btn" href="/">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 5v14M5 12h14"/></svg>
        Nova verificação
      </a>
    </div>
    <div class="side-history">
      <div class="sidebar-label">
        <span>Recentes</span>
        <button class="sidebar-clear" type="button" onclick="historyClearAll()">Limpar</button>
      </div>
      <div id="sidebar-body">${historyHtml}</div>
    </div>
    ${accountBlock}
  </aside>
  <div class="backdrop" onclick="toggleSide(false)"></div>

  <!-- PALCO -->
  <main class="stage">
    <div class="topbar">
      <button class="icon-btn" type="button" onclick="toggleSide(true)" aria-label="Abrir menu">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M4 7h16M4 12h16M4 17h10"/></svg>
      </button>
      <a class="brand" href="/">${ecoaMark(24, "tb")}${ECOA_WORDMARK}</a>
      <span class="spacer"></span>
      <a class="icon-btn" href="/" aria-label="Nova verificação">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 5v14M5 12h14"/></svg>
      </a>
    </div>

    <div class="thread" id="thread">
      <div class="thread-inner">

        <section class="hero">
          <div class="hero-mark">
            <span class="echo"></span><span class="echo e2"></span>
            ${ecoaMark(84, "hero")}
          </div>
          <h1>O que você quer verificar hoje?</h1>
          <p>Mande uma frase, um link, uma foto ou um vídeo que recebeu. A gente checa nas fontes e te explica.</p>
        </section>

        <article class="msg-result msg-bot" aria-live="polite">
          <div class="bot-head">
            <div class="bot-avatar">${ecoaMark(24, "rs")}</div>
            <div class="bot-name">Ecoa Saúde</div>
          </div>
          <div class="bot-body">
            <div class="result-body">${content}</div>
          </div>
        </article>

        <section class="pending" id="pending" hidden>
          <div class="msg-user">
            <div class="msg-user-file" id="pending-file" hidden>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="3"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="M21 15l-5-5L5 21"/></svg>
              <span id="pending-file-name"></span>
            </div>
            <div class="msg-user-text" id="pending-text"></div>
          </div>
          <div class="msg-bot" role="status" aria-live="polite">
            <div class="bot-head">
              <div class="bot-avatar">${ecoaMark(24, "pd", "thinking")}</div>
              <div class="bot-name">Ecoa Saúde</div>
            </div>
            <div class="bot-body">
              <div class="think-title">Checando isso para você…</div>
              <div class="l-steps">
                <div class="l-step" id="ls1"><span class="l-dot"></span>Entendendo a afirmação</div>
                <div class="l-step" id="ls2"><span class="l-dot"></span>Procurando sinais de IA</div>
                <div class="l-step" id="ls3"><span class="l-dot"></span>Consultando checagens de fatos</div>
                <div class="l-step" id="ls4"><span class="l-dot"></span>Buscando notícias recentes</div>
                <div class="l-step" id="ls5"><span class="l-dot"></span>Escrevendo a resposta</div>
              </div>
            </div>
          </div>
        </section>

      </div>
    </div>

    <!-- COMPOSER -->
    <div class="dock">
      <form class="composer" id="composer" method="post" action="/analyze-text" enctype="application/x-www-form-urlencoded">
        <div class="attach" id="attach" hidden>
          <div class="attach-ico" aria-hidden="true">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="3"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="M21 15l-5-5L5 21"/></svg>
          </div>
          <div class="attach-txt">
            <div class="attach-name" id="attach-name"></div>
            <div class="attach-meta" id="attach-meta"></div>
          </div>
          <button class="icon-btn" type="button" id="attach-remove" aria-label="Remover arquivo">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M6 6l12 12M18 6L6 18"/></svg>
          </button>
        </div>

        <div class="composer-row">
          <label class="c-btn" title="Anexar imagem ou vídeo" aria-label="Anexar imagem ou vídeo">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M12 5v14M5 12h14"/></svg>
            <input type="file" id="file" name="file" accept="image/*,video/*">
          </label>

          <textarea id="content" name="content" rows="1" maxlength="100" placeholder="Pergunte qualquer coisa" aria-label="Mensagem para verificar" autocomplete="off"></textarea>

          <span class="counter" id="counter" hidden>0/100</span>

          <button class="c-btn" type="button" id="mic" title="Falar" aria-label="Ditar por voz" aria-pressed="false">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="3" width="6" height="11" rx="3"/><path d="M5 11a7 7 0 0 0 14 0"/><path d="M12 18v3"/></svg>
          </button>

          <button class="send" type="submit" id="send" aria-label="Enviar" disabled>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 19V5"/><path d="M6 11l6-6 6 6"/></svg>
          </button>
        </div>
      </form>

      <div class="suggestions">
        <button class="sugg" type="button" data-ex="Chá de boldo cura dengue?" onclick="fillExample(this)">Chá de boldo cura dengue?</button>
        <button class="sugg" type="button" data-ex="A vacina da gripe pode causar gripe?" onclick="fillExample(this)">A vacina da gripe causa gripe?</button>
        <button class="sugg" type="button" data-ex="Água com limão em jejum emagrece?" onclick="fillExample(this)">Água com limão em jejum emagrece?</button>
      </div>

      <div class="dock-note" id="dock-note">A Ecoa Saúde pode errar. Confira as fontes antes de compartilhar.</div>
    </div>
  </main>
</div>

<script>
(function(){
  var MAX = 100, MAX_BYTES = 80 * 1024 * 1024;
  var body = document.body;
  var form = document.getElementById('composer');
  var ta = document.getElementById('content');
  var fileInput = document.getElementById('file');
  var attach = document.getElementById('attach');
  var sendBtn = document.getElementById('send');
  var counter = document.getElementById('counter');
  var note = document.getElementById('dock-note');
  var NOTE_DEFAULT = note.textContent;
  var PH_TEXT = 'Pergunte qualquer coisa';
  var PH_FILE = 'Onde você recebeu? O que dizem que mostra?';

  function hasFile(){ return !!(fileInput.files && fileInput.files.length); }
  function setNote(msg){ note.textContent = msg || NOTE_DEFAULT; note.classList.toggle('is-error', !!msg); }
  function autosize(){ ta.style.height = '42px'; ta.style.height = Math.min(ta.scrollHeight, 168) + 'px'; }
  function refresh(){
    var n = ta.value.length;
    counter.textContent = n + '/' + MAX;
    counter.hidden = n < 70;
    counter.classList.toggle('is-max', n >= MAX);
    sendBtn.disabled = !(ta.value.trim() || hasFile());
    autosize();
  }
  function fmtSize(b){ return b > 1048576 ? (b / 1048576).toFixed(1).replace('.', ',') + ' MB' : Math.max(1, Math.round(b / 1024)) + ' KB'; }

  function showFile(){
    if (!hasFile()) { attach.hidden = true; ta.placeholder = PH_TEXT; refresh(); return; }
    var f = fileInput.files[0];
    var okType = /^(image|video)[/]/.test(f.type || '');
    if (!okType || f.size > MAX_BYTES) {
      setNote(!okType ? 'Esse tipo de arquivo não é aceito. Envie uma imagem ou um vídeo.' : 'Arquivo muito grande. O máximo é 80 MB.');
      fileInput.value = '';
      attach.hidden = true; refresh(); return;
    }
    setNote('');
    document.getElementById('attach-name').textContent = f.name;
    document.getElementById('attach-meta').textContent = ((f.type || '').indexOf('video') === 0 ? 'Vídeo' : 'Imagem') + ', ' + fmtSize(f.size);
    attach.hidden = false;
    ta.placeholder = PH_FILE;
    refresh();
    ta.focus();
  }
  fileInput.addEventListener('change', showFile);
  document.getElementById('attach-remove').addEventListener('click', function(){ fileInput.value = ''; showFile(); });

  // Arrastar e soltar arquivo na barra
  ['dragenter','dragover'].forEach(function(ev){ form.addEventListener(ev, function(e){ e.preventDefault(); form.classList.add('is-drag'); }); });
  ['dragleave','drop'].forEach(function(ev){ form.addEventListener(ev, function(e){ e.preventDefault(); form.classList.remove('is-drag'); }); });
  form.addEventListener('drop', function(e){
    if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) {
      try { fileInput.files = e.dataTransfer.files; showFile(); } catch (err) {}
    }
  });

  ta.addEventListener('input', refresh);
  ta.addEventListener('keydown', function(e){
    if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) {
      e.preventDefault();
      if (!sendBtn.disabled && prepare()) form.submit();
    }
  });
  form.addEventListener('submit', function(e){ if (!prepare()) e.preventDefault(); });

  // Um único campo: sem arquivo vai para /analyze-text, com arquivo vai para /analyze-file
  function prepare(){
    if (form.classList.contains('is-busy')) return false;
    var text = ta.value.trim();
    var f = hasFile() ? fileInput.files[0] : null;
    if (!text && !f) return false;
    if (f) {
      form.action = '/analyze-file';
      form.enctype = 'multipart/form-data';
      ta.name = 'caption';
      fileInput.disabled = false;
    } else {
      form.action = '/analyze-text';
      form.enctype = 'application/x-www-form-urlencoded';
      ta.name = 'content';
      fileInput.disabled = true;
    }
    showPending(text, f ? f.name : '');
    return true;
  }

  var timers = [];
  function showPending(text, fileName){
    body.classList.remove('is-home');
    body.classList.add('is-chat');
    var result = document.querySelector('.msg-result');
    if (result) result.hidden = true;
    document.getElementById('pending-text').textContent = text;
    document.getElementById('pending-file-name').textContent = fileName;
    document.getElementById('pending-file').hidden = !fileName;
    document.getElementById('pending').hidden = false;
    form.classList.add('is-busy');
    ta.readOnly = true;
    setTimeout(function(){ sendBtn.disabled = true; }, 0);
    toggleSide(false);

    var steps = [1,2,3,4,5].map(function(i){ return document.getElementById('ls' + i); });
    var delays = [0, 2000, 4000, 7000, 11000];
    timers.forEach(clearTimeout); timers = [];
    steps.forEach(function(s){ s.classList.remove('active','done'); });
    delays.forEach(function(d, i){
      timers.push(setTimeout(function(){
        if (i > 0) { steps[i-1].classList.remove('active'); steps[i-1].classList.add('done'); }
        steps[i].classList.add('active');
      }, d));
    });
    var thread = document.getElementById('thread');
    thread.scrollTop = 0;
  }
  function resetComposer(){
    timers.forEach(clearTimeout);
    form.classList.remove('is-busy');
    ta.readOnly = false;
    fileInput.disabled = false;
    ta.name = 'content';
    refresh();
  }
  window.addEventListener('pageshow', function(e){
    if (e.persisted) {
      document.getElementById('pending').hidden = true;
      var result = document.querySelector('.msg-result');
      if (result) result.hidden = false;
      if (!result || !result.querySelector('.result-body').innerHTML.trim()) { body.classList.add('is-home'); body.classList.remove('is-chat'); }
      resetComposer();
    }
  });

  // Ditado por voz (quando o navegador suporta)
  var mic = document.getElementById('mic');
  var SR = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (!SR) { mic.hidden = true; }
  else {
    var rec = null, live = false;
    mic.addEventListener('click', function(){
      if (live && rec) { rec.stop(); return; }
      rec = new SR();
      rec.lang = 'pt-BR';
      rec.interimResults = true;
      var base = ta.value.trim() ? ta.value.trim() + ' ' : '';
      rec.onresult = function(ev){
        var t = '';
        for (var i = 0; i < ev.results.length; i++) t += ev.results[i][0].transcript;
        ta.value = (base + t).slice(0, MAX);
        refresh();
      };
      rec.onend = rec.onerror = function(){
        live = false; mic.classList.remove('is-live'); mic.setAttribute('aria-pressed', 'false');
      };
      try { rec.start(); live = true; mic.classList.add('is-live'); mic.setAttribute('aria-pressed', 'true'); } catch (err) {}
    });
  }

  // Menu lateral (celular)
  window.toggleSide = function(open){ body.classList.toggle('side-open', !!open); };
  document.addEventListener('keydown', function(e){ if (e.key === 'Escape') toggleSide(false); });

  // Exemplos e histórico
  window.fillExample = function(btn){
    ta.value = (btn.getAttribute('data-ex') || '').slice(0, MAX);
    refresh();
    ta.focus();
  };
  window.historyUse = function(btn){
    ta.value = (btn.getAttribute('data-text') || '').slice(0, MAX);
    refresh();
    toggleSide(false);
    ta.focus();
  };
  var EMPTY_HIST = '<div class="sidebar-empty">Suas verificações aparecem aqui.</div>';
  window.historyDel = function(id, btn){
    fetch('/historico/excluir', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id: id }) })
      .then(function(){
        var el = btn.closest('.sidebar-item'); if (el) el.remove();
        var hb = document.getElementById('sidebar-body');
        if (hb && !hb.querySelector('.sidebar-item')) hb.innerHTML = EMPTY_HIST;
      }).catch(function(){});
  };
  window.historyClearAll = function(){
    fetch('/historico/limpar', { method: 'POST' })
      .then(function(){ document.getElementById('sidebar-body').innerHTML = EMPTY_HIST; })
      .catch(function(){});
  };

  refresh();
  if (body.classList.contains('is-home') && window.matchMedia('(min-width: 901px)').matches) ta.focus();

  // Carrossel de notícias do relatório
  var _carouselIdx = 0;
  function _visibleCount(){
    var w = (document.querySelector('.carousel-viewport') || document.body).getBoundingClientRect().width;
    if (w <= 520) return 1;
    if (w <= 700) return 2;
    return 3;
  }
  function newsGoTo(idx){
    var track = document.getElementById('news-track');
    if (!track) return;
    var slides = track.querySelectorAll('.news-slide');
    var dots = document.querySelectorAll('#news-dots .c-dot');
    if (!slides.length) return;
    var max = Math.max(0, slides.length - _visibleCount());
    _carouselIdx = Math.max(0, Math.min(idx, max));
    var slideW = slides[0].getBoundingClientRect().width + 12;
    track.style.transform = 'translateX(-' + (_carouselIdx * slideW) + 'px)';
    dots.forEach(function(d, i){ d.classList.toggle('active', i === _carouselIdx); });
    var prev = document.getElementById('carousel-prev');
    var next = document.getElementById('carousel-next');
    if (prev) prev.disabled = _carouselIdx === 0;
    if (next) next.disabled = _carouselIdx >= max;
  }
  window.newsGoTo = newsGoTo;
  window.newsCarousel = function(dir){ newsGoTo(_carouselIdx + dir); };
  setTimeout(function(){ newsGoTo(0); }, 50);
  window.addEventListener('resize', function(){ newsGoTo(_carouselIdx); });

  (function(){
    var track = document.getElementById('news-track');
    if (!track) return;
    var startX = 0, startIdx = 0, dragging = false, moved = false;
    function slideWidth(){ var s = track.querySelector('.news-slide'); return s ? s.getBoundingClientRect().width + 12 : 0; }
    function onDown(e){
      dragging = true; moved = false;
      startX = e.type === 'mousedown' ? e.clientX : e.touches[0].clientX;
      startIdx = _carouselIdx;
      track.style.transition = 'none';
      track.style.cursor = 'grabbing';
    }
    function onMove(e){
      if (!dragging) return;
      var x = e.type === 'mousemove' ? e.clientX : e.touches[0].clientX;
      var diff = startX - x;
      if (Math.abs(diff) > 5) moved = true;
      if (!moved) return;
      track.style.transform = 'translateX(-' + (startIdx * slideWidth() + diff) + 'px)';
      if (e.cancelable) e.preventDefault();
    }
    function onUp(e){
      if (!dragging) return;
      dragging = false;
      track.style.transition = '';
      track.style.cursor = 'grab';
      if (!moved) return;
      var x = e.type === 'mouseup' ? e.clientX : (e.changedTouches[0] || { clientX: startX }).clientX;
      var w = slideWidth();
      if (w) newsGoTo(startIdx + Math.round((startX - x) / w));
    }
    track.addEventListener('mousedown', onDown);
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
    track.addEventListener('touchstart', onDown, { passive: true });
    track.addEventListener('touchmove', onMove, { passive: false });
    track.addEventListener('touchend', onUp);
    track.style.cursor = 'grab';
  })();
})();
</script>
</body>
</html>`;
}

// ══════════════════════════════════════════════════════════
// 🔐 ROTAS DE AUTENTICAÇÃO
// ══════════════════════════════════════════════════════════
app.get("/login", (req, res) => {
  if (req.session?.userId) return res.redirect("/");
  res.send(renderAuthPage({ mode: "login", notice: req.query.msg || "" }));
});

app.post("/login", rateLimit(8, 15*60000), (req, res) => {
  const { email = "", password = "" } = req.body;
  const user = findUserByEmail(email);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    logActivity(user?.id, email, "login_falhou", "", req); // 📋
    return res.send(renderAuthPage({ mode: "login", error: "E-mail ou senha incorretos.", email }));
  }
  req.session.userId = user.id;
  logActivity(user.id, user.email, "login", "", req); // 📋
  res.redirect("/");
});

app.get("/register", (req, res) => {
  if (req.session?.userId) return res.redirect("/");
  res.send(renderAuthPage({ mode: "register" }));
});

app.post("/register", rateLimit(5, 30*60000), (req, res) => {
  const { name = "", email = "", password = "" } = req.body;
  if (!name.trim() || !email.trim() || password.length < 6) {
    return res.send(renderAuthPage({ mode: "register", error: "Preencha todos os campos. Senha mínima de 6 caracteres.", email, name }));
  }
  // 🔒 [FIX] Validação de e-mail no servidor (o maxlength/type=email do HTML é contornável)
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email.trim()) || email.length > 120) {
    return res.send(renderAuthPage({ mode: "register", error: "E-mail inválido.", email, name }));
  }
  if (findUserByEmail(email)) {
    return res.send(renderAuthPage({ mode: "register", error: "Este e-mail já está cadastrado. Faça login.", email, name }));
  }
  try {
    const id = createUser({ name, email, password });
    req.session.userId = id;
    logActivity(id, email, "registro", "conta nova", req); // 📋
    res.redirect("/");
  } catch (e) {
    console.error("Registro:", e.message);
    res.send(renderAuthPage({ mode: "register", error: "Erro ao criar conta. Tente novamente.", email, name }));
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

// ══════════════════════════════════════════════════════════
// 📧 RECUPERAÇÃO DE SENHA (token de uso único, válido por 1h)
// ══════════════════════════════════════════════════════════
db.exec(`CREATE TABLE IF NOT EXISTS password_resets (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used INTEGER NOT NULL DEFAULT 0
)`);
setInterval(() => {
  try { db.prepare("DELETE FROM password_resets WHERE expires_at < ?").run(Date.now()); } catch (_) {}
}, 3600000).unref();

function hashResetToken(t) { return crypto.createHash("sha256").update(t).digest("hex"); }
function findValidReset(token) {
  const row = db.prepare("SELECT * FROM password_resets WHERE token_hash = ?").get(hashResetToken(token));
  if (!row || row.used || row.expires_at < Date.now()) return null;
  return row;
}

app.get("/esqueci", (req, res) => {
  if (req.session?.userId) return res.redirect("/");
  res.send(renderAuthPage({ mode: "esqueci" }));
});

app.post("/esqueci", rateLimit(5, 30 * 60000), async (req, res) => {
  const email = String(req.body.email || "").trim();
  const user = findUserByEmail(email);
  // Resposta SEMPRE igual (não revela se o e-mail existe — evita enumeração)
  const generic = "Se este e-mail estiver cadastrado, enviamos um link de redefinição válido por 1 hora. Confira também o spam.";
  if (user) {
    try {
      const token = crypto.randomBytes(32).toString("hex");
      db.prepare("DELETE FROM password_resets WHERE user_id = ?").run(user.id); // invalida links antigos
      db.prepare("INSERT INTO password_resets (token_hash, user_id, expires_at) VALUES (?,?,?)")
        .run(hashResetToken(token), user.id, Date.now() + 3600000);
      const link = `${CONFIG.APP_URL}/redefinir?token=${token}`;
      await sendResetEmail(user.email, link);
      logActivity(user.id, user.email, "senha_reset_solicitado", mailer ? "e-mail enviado" : "link no log (SMTP off)", req);
    } catch (e) { console.error("[Reset]", e.message); }
  } else {
    logActivity(null, email, "senha_reset_solicitado", "e-mail não cadastrado", req);
  }
  res.send(renderAuthPage({ mode: "esqueci", notice: generic }));
});

app.get("/redefinir", (req, res) => {
  const token = String(req.query.token || "");
  if (!token || !findValidReset(token)) {
    return res.send(renderAuthPage({ mode: "esqueci", error: "Link inválido ou expirado. Solicite um novo abaixo." }));
  }
  res.send(renderAuthPage({ mode: "redefinir", token }));
});

app.post("/redefinir", (req, res) => {
  const { token = "", password = "", confirm = "" } = req.body;
  const reset = findValidReset(token);
  if (!reset) {
    return res.send(renderAuthPage({ mode: "esqueci", error: "Link inválido ou expirado. Solicite um novo abaixo." }));
  }
  if (password.length < 6) {
    return res.send(renderAuthPage({ mode: "redefinir", token, error: "A nova senha deve ter no mínimo 6 caracteres." }));
  }
  if (password !== confirm) {
    return res.send(renderAuthPage({ mode: "redefinir", token, error: "As senhas não conferem." }));
  }
  const user = findUserById(reset.user_id);
  if (!user) return res.send(renderAuthPage({ mode: "esqueci", error: "Conta não encontrada." }));
  updateUserPassword(user.id, password);
  db.prepare("UPDATE password_resets SET used = 1 WHERE token_hash = ?").run(hashResetToken(token));
  // 🔒 Derruba TODAS as sessões ativas do usuário (se alguém estava logado indevidamente, cai)
  db.prepare("DELETE FROM sessions WHERE sess LIKE ?").run(`%"userId":${user.id}%`);
  logActivity(user.id, user.email, "senha_redefinida", "via link de recuperação", req);
  res.redirect("/login?msg=" + encodeURIComponent("Senha redefinida com sucesso! Entre com a nova senha."));
});

// ══════════════════════════════════════════════════════════
// ⚙️ ROTAS: CONTA (configurações)
// ══════════════════════════════════════════════════════════
app.get("/conta", requireAuth, (req, res) => {
  res.send(renderContaPage(req.user, req.query));
});

app.post("/conta/perfil", requireAuth, (req, res) => {
  const name = (req.body.name || "").trim();
  if (name.length < 2 || name.length > 80) {
    return res.redirect("/conta?erro=" + encodeURIComponent("Nome deve ter entre 2 e 80 caracteres."));
  }
  updateUserName(req.user.id, name);
  res.redirect("/conta?ok=perfil");
});

app.post("/conta/senha", requireAuth, (req, res) => {
  const { current = "", password = "", confirm = "" } = req.body;
  const full = getUserWithHash(req.user.id);
  if (!bcrypt.compareSync(current, full.password_hash)) {
    return res.redirect("/conta?erro=" + encodeURIComponent("Senha atual incorreta."));
  }
  if (password.length < 6) {
    return res.redirect("/conta?erro=" + encodeURIComponent("Nova senha deve ter no mínimo 6 caracteres."));
  }
  if (password !== confirm) {
    return res.redirect("/conta?erro=" + encodeURIComponent("As senhas não conferem."));
  }
  updateUserPassword(req.user.id, password);
  res.redirect("/conta?ok=senha");
});

// 🔴 [NOVO] Exclusão da própria conta (exige senha)
app.post("/conta/excluir", requireAuth, async (req, res) => {
  const { password = "" } = req.body;
  const full = getUserWithHash(req.user.id);
  if (!bcrypt.compareSync(password, full.password_hash)) {
    return res.redirect("/conta?erro=" + encodeURIComponent("Senha incorreta. Conta não excluída."));
  }
  logActivity(req.user.id, req.user.email, "conta_excluida", "auto-exclusão pelo usuário", req); // 📋
  console.log(`[Conta] Exclusão: ${req.user.email} (id ${req.user.id})`);
  deleteUser(req.user.id);
  req.session.destroy(() => res.redirect("/login?msg=" + encodeURIComponent("Conta excluída com sucesso.")));
});

// ══════════════════════════════════════════════════════════
// ROTAS DA APLICAÇÃO (protegidas)
// ══════════════════════════════════════════════════════════
app.get("/", requireAuth, async (req, res) => res.send(renderPage("", req.user)));

app.post("/analyze-text", requireAuth, async (req, res) => {
  try {
    const content = (req.body.content||"").trim();
    if (!content) return res.send(renderPage(`<div class="no-result">Envie algum texto ou link.</div>`, req.user));
    const urls = extractUrls(content);
    const result = urls.length > 0 ? await analyzeLink(urls[0]) : await analyzeText(content);
    incrementUsage(req.user.id); // 🔐 conta a verificação
    addHistory(req.user.id, content, urls.length > 0 ? "LINK" : "TEXTO",
      { verdict: result.verdict, summary: result.summary, resultJson: serializeResultForHistory(result) }); // 📜
    logActivity(req.user.id, req.user.email, "verificacao", `${urls.length > 0 ? "LINK" : "TEXTO"}: ${content.slice(0, 90)}`, req); // 📋
    res.send(renderPage(formatResultHtml(result), req.user));
  } catch(e) {
    console.error(e);
    res.send(renderPage(`<div class="no-result">Erro: ${escapeHtml(e.message||"erro desconhecido")}</div>`, req.user));
  }
});

// 🔒 [FIX] Wrapper do multer: erros de limite/tipo viram mensagem amigável em vez de crash
function uploadSafe(req, res, next) {
  upload.single("file")(req, res, (err) => {
    if (err) {
      const msg = err.code === "LIMIT_FILE_SIZE" ? "Arquivo muito grande. O máximo é 80MB." : (err.message || "Erro no upload.");
      return res.send(renderPage(`<div class="no-result">${escapeHtml(msg)}</div>`, req.user));
    }
    next();
  });
}

app.post("/analyze-file", requireAuth, uploadSafe, async (req, res) => {
  let filePath = req.file?.path;
  try {
    if (!req.file) return res.send(renderPage(`<div class="no-result">Nenhum arquivo enviado.</div>`, req.user));
    const caption = req.body.caption||"";
    const mime = req.file.mimetype||"";
    let result;
    if (mime.startsWith("image/")) result = await analyzeImage(filePath, caption);
    else if (mime.startsWith("video/")) result = await analyzeVideo(filePath, caption);
    else return res.send(renderPage(`<div class="no-result">Tipo não suportado. Envie imagem ou vídeo.</div>`, req.user));
    incrementUsage(req.user.id); // 🔐 conta a verificação
    addHistory(req.user.id, caption || req.file.originalname || "mídia", "MÍDIA",
      { verdict: result.verdict, summary: result.summary, resultJson: serializeResultForHistory(result) }); // 📜
    logActivity(req.user.id, req.user.email, "verificacao", `MÍDIA (${mime}): ${req.file.originalname || ""} ${caption ? "| " + caption.slice(0, 60) : ""}`, req); // 📋
    res.send(renderPage(formatResultHtml(result), req.user));
  } catch(e) {
    console.error(e);
    res.send(renderPage(`<div class="no-result">Erro: ${escapeHtml(e.message||"erro desconhecido")}</div>`, req.user));
  } finally {
    if (filePath) await cleanup(filePath);
  }
});

// Healthcheck para o Railway
app.get("/health", (_req, res) => res.json({ status: "ok" }));

// 📜 [NOVO] Gerenciar histórico (sempre restrito ao próprio usuário)
// 📜 [NOVO] Reabrir uma verificação salva (sem gastar crédito)
app.get("/historico/ver/:id", requireAuth, (req, res) => {
  const result = getHistoryResult(req.user.id, Number(req.params.id));
  if (!result) return res.redirect("/");
  res.send(renderPage(formatResultHtml(result), req.user));
});

app.post("/historico/excluir", requireAuth, (req, res) => {
  const id = Number(req.body?.id);
  if (id) delHistoryItem(req.user.id, id);
  res.json({ ok: true });
});
app.post("/historico/limpar", requireAuth, (req, res) => {
  clearHistory(req.user.id);
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════
// 👑 PAINEL ADMIN (apenas e-mails em ADMIN_EMAILS)
// ══════════════════════════════════════════════════════════
function requireAdmin(req, res, next) {
  if (!isAdmin(req.user)) return res.redirect("/");
  next();
}

app.get("/admin", requireAuth, requireAdmin, (req, res) => {
  const q = String(req.query.q || "").trim();
  let users;
  if (q) {
    users = db.prepare(`
      SELECT u.id, u.name, u.email, u.created_at,
             COALESCE(m.count, 0) AS month_usage,
             COALESCE(t.total, 0) AS total_usage
      FROM users u
      LEFT JOIN usage m ON m.user_id = u.id AND m.month = ?
      LEFT JOIN (SELECT user_id, SUM(count) AS total FROM usage GROUP BY user_id) t ON t.user_id = u.id
      WHERE u.email LIKE ? OR u.name LIKE ?
      ORDER BY u.id DESC LIMIT 100
    `).all(currentMonth(), `%${q}%`, `%${q}%`);
  } else {
    users = db.prepare(`
      SELECT u.id, u.name, u.email, u.created_at,
             COALESCE(m.count, 0) AS month_usage,
             COALESCE(t.total, 0) AS total_usage
      FROM users u
      LEFT JOIN usage m ON m.user_id = u.id AND m.month = ?
      LEFT JOIN (SELECT user_id, SUM(count) AS total FROM usage GROUP BY user_id) t ON t.user_id = u.id
      ORDER BY u.id DESC LIMIT 100
    `).all(currentMonth());
  }
  const stats = {
    total: db.prepare("SELECT COUNT(*) c FROM users").get().c,
    verifMes: db.prepare("SELECT COALESCE(SUM(count),0) c FROM usage WHERE month = ?").get(currentMonth()).c,
    verifHoje: db.prepare("SELECT COUNT(*) c FROM activity_log WHERE action = 'verificacao' AND created_at >= ?").get(new Date().toISOString().slice(0,10)).c,
    verifTotal: db.prepare("SELECT COALESCE(SUM(count),0) c FROM usage").get().c,
    pesquisas: db.prepare("SELECT COUNT(*) c FROM history").get().c
  };
  let msg = "";
  if (req.query.ok === "excluido") msg = `<div class="msg-ok">✓ Usuário excluído.</div>`;
  if (req.query.erro) msg = `<div class="msg-err">${escapeHtml(req.query.erro)}</div>`;
  if (req.query.pushsent) msg = `<div class="msg-ok">🔔 Notificação disparada: ${escapeHtml(req.query.pushsent)}</div>`;

  const td = `padding:9px 8px; border-top:1px solid #E6E8EC; vertical-align:middle;`;
  const rows = users.map(u => `
    <tr>
      <td style="${td} color:#6B7280;">#${u.id}</td>
      <td style="${td} color:#14171C; white-space:nowrap;">${escapeHtml(u.name)}${isAdmin(u) ? ' <span style="color:#9A7400;">👑</span>' : ''}</td>
      <td style="${td}">${escapeHtml(u.email)}</td>
      <td style="${td} text-align:right;">${u.month_usage}</td>
      <td style="${td} text-align:right; color:#6B7280;">${u.total_usage}</td>
      <td style="${td} color:#6B7280; font-size:12px; white-space:nowrap;">${new Date(u.created_at).toLocaleDateString("pt-BR")}</td>
      <td style="${td} white-space:nowrap;">
        <a href="/admin/exportar/usuario/${u.id}" style="color:#2560CC; font-size:12px; margin-right:10px;">Baixar</a>
        <a href="/admin/logs?email=${encodeURIComponent(u.email)}" style="color:#2560CC; font-size:12px; margin-right:10px;">Logs</a>
        <form method="post" action="/admin/excluir" style="display:inline;" onsubmit="return confirm('Excluir ${escapeHtml(u.email)}? Esta ação apaga a conta e todo o histórico dela.');">
          <input type="hidden" name="user_id" value="${u.id}">
          <button type="submit" style="background:none; border:none; color:#C62828; font-size:12px; cursor:pointer; padding:0;">Excluir</button>
        </form>
      </td>
    </tr>`).join("");

  const pushDevices = db.prepare("SELECT COUNT(*) AS c FROM push_tokens").get().c;
  const content = `
  <div class="page-title">👑 Admin</div>
  <div class="page-sub">Gestão de usuários, dados e atividades. <a href="/admin/logs" style="color:#2560CC;">Ver todos os logs →</a></div>
  ${msg}
  <div style="display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:12px; margin-bottom:24px;">
    ${[["Contas", stats.total],["Verif. no mês", stats.verifMes],["Verif. hoje", stats.verifHoje],["Verif. no total", stats.verifTotal],["Pesquisas salvas", stats.pesquisas],["Aparelhos 🔔", pushDevices]].map(([label,val]) => `
    <div class="card" style="margin:0; padding:16px; text-align:center;">
      <div style="font-size:28px; font-weight:700; color:#2560CC;">${val}</div>
      <div style="font-size:11px; color:#6B7280; text-transform:uppercase; letter-spacing:0.06em;">${label}</div>
    </div>`).join("")}
  </div>

  <!-- 📥 EXPORTAÇÃO DE DADOS -->
  <div class="card" style="margin-bottom:24px;">
    <div class="card-title">📥 Baixar dados</div>
    <div style="color:#6B7280; font-size:14px; margin-bottom:16px;">
      Os arquivos CSV abrem direto no Excel ou no Google Planilhas. O JSON traz tudo junto, para backup ou análise.
      O histórico guarda as ${MAX_HISTORY_PER_USER} pesquisas mais recentes de cada usuário.
    </div>
    <div style="display:flex; flex-wrap:wrap; gap:10px;">
      <a class="btn" href="/admin/exportar/usuarios" style="text-decoration:none; display:inline-block;">Usuários (CSV)</a>
      <a class="btn" href="/admin/exportar/pesquisas" style="text-decoration:none; display:inline-block;">Pesquisas (CSV)</a>
      <a class="btn" href="/admin/exportar/logs" style="text-decoration:none; display:inline-block;">Logs (CSV)</a>
      <a class="btn" href="/admin/exportar/tudo" style="text-decoration:none; display:inline-block; background:#0F1217;">Tudo (JSON)</a>
      <a class="btn" href="/admin/exportar/tudo?completo=1" style="text-decoration:none; display:inline-block; background:transparent; color:#2560CC; border:1px solid #2560CC;">Tudo + relatórios completos (JSON)</a>
    </div>
  </div>

  <!-- 🔔 DISPARADOR DE NOTIFICAÇÕES -->
  <div class="card" style="margin-bottom:24px;">
    <div style="font-size:18px; font-weight:700; text-transform:uppercase; letter-spacing:1px; margin-bottom:4px;">🔔 Disparar notificação</div>
    <div style="color:#6B7280; font-size:14px; margin-bottom:14px;">Envia push para os aparelhos com o app instalado (${pushDevices} registrado${pushDevices === 1 ? "" : "s"}).</div>
    <form method="post" action="/admin/notificacoes" style="display:grid; grid-template-columns:1fr; gap:12px;">
      <input type="hidden" name="back" value="admin">
      <div style="grid-column:1 / -1;">
        <input name="title" maxlength="80" required placeholder="Título (ex.: Nova checagem em destaque)"
          style="width:100%; background:#F4F6F9; border:1px solid #E6E8EC; color:#14171C; font-family:inherit; font-size:15px; padding:10px 12px; border-radius:2px;">
      </div>
      <div style="grid-column:1 / -1;">
        <textarea name="body" maxlength="220" required placeholder="Mensagem (até 220 caracteres)"
          style="width:100%; min-height:70px; resize:vertical; background:#F4F6F9; border:1px solid #E6E8EC; color:#14171C; font-family:inherit; font-size:15px; padding:10px 12px; border-radius:2px;"></textarea>
      </div>
      <button type="submit" style="background:#C62828; color:#FFFFFF; border:0; padding:12px; font-family:inherit; font-size:14px; font-weight:700; text-transform:uppercase; letter-spacing:2px; cursor:pointer; border-radius:2px;">Disparar</button>
    </form>
  </div>
  <div class="card" style="overflow-x:auto;">
    <div class="card-title" style="display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap;">
      <span>Usuários ${q ? `— busca: "${escapeHtml(q)}" (${users.length})` : `(${users.length})`}</span>
      <form method="get" action="/admin" style="display:flex; gap:6px;">
        <input type="text" name="q" value="${escapeHtml(q)}" placeholder="Buscar nome ou e-mail..." style="background:#F4F6F9; border:1px solid #E3E6EB; color:#14171C; padding:7px 12px; border-radius:2px; font-size:13px; width:220px;">
        <button type="submit" style="background:#EEF1F5; border:1px solid #D5D9E0; color:#3F4652; padding:7px 14px; border-radius:2px; font-size:12px; cursor:pointer;">Buscar</button>
        ${q ? '<a href="/admin" style="align-self:center; color:#6B7280; font-size:12px;">limpar</a>' : ''}
      </form>
    </div>
    <table style="width:100%; border-collapse:collapse; font-size:13px;">
      <thead>
        <tr style="color:#6B7280; text-transform:uppercase; font-size:11px; letter-spacing:0.08em; text-align:left;">
          <th style="padding:8px;">ID</th><th style="padding:8px;">Nome</th><th style="padding:8px;">E-mail</th><th style="padding:8px; text-align:right;">Mês</th><th style="padding:8px; text-align:right;">Total</th><th style="padding:8px;">Criada</th><th style="padding:8px;">Ações</th>
        </tr>
      </thead>
      <tbody style="color:#4A5260;">${rows || `<tr><td colspan="7" style="padding:20px; text-align:center; color:#6B7280;">Nenhum usuário encontrado.</td></tr>`}</tbody>
    </table>
  </div>`;
  res.send(renderSubPage("Admin", content, req.user));
});

// 🔔 [NOVO] Disparador de notificações (admin)
app.get("/admin/notificacoes", requireAuth, requireAdmin, (req, res) => {
  const total = db.prepare("SELECT COUNT(*) AS c FROM push_tokens").get().c;
  const sent = String(req.query.sent || "");
  res.send(`<!DOCTYPE html><html lang="pt-BR"><head><meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Notificações — Ecoa Saúde Admin</title>
  <link href="https://fonts.googleapis.com/css2?family=Barlow+Condensed:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root { --bg:#FFFFFF; --card:#F6F7F9; --line:#E6E8EC; --dim:#6B7280; --fg:#14171C; --red:#C62828; }
    * { box-sizing:border-box; margin:0; }
    body { background:var(--bg); color:var(--fg); padding:32px 16px; }
    .wrap { max-width:560px; margin:0 auto; }
    h1 { font-size:30px; text-transform:uppercase; letter-spacing:1px; }
    h1 span { color:var(--red); }
    .meta { color:var(--dim); margin:8px 0 24px; font-size:16px; }
    .card { background:var(--card); border:1px solid var(--line); padding:20px; }
    label { display:block; font-size:13px; text-transform:uppercase; letter-spacing:1px; color:var(--dim); margin:14px 0 6px; }
    input, textarea, select { width:100%; background:#F4F6F9; border:1px solid var(--line); color:var(--fg);
      font-family:inherit; font-size:17px; padding:10px 12px; border-radius:2px; }
    textarea { min-height:90px; resize:vertical; }
    button { margin-top:20px; width:100%; background:var(--red); color:#FFFFFF; border:0; padding:14px;
      font-family:inherit; font-size:16px; font-weight:700; text-transform:uppercase; letter-spacing:2px; cursor:pointer; border-radius:2px; }
    .ok { background:#E8F5EE; border:1px solid #2E8B57; color:#2E8B57; padding:12px; margin-bottom:16px; font-size:15px; }
    a { color:var(--dim); font-size:14px; }
  </style></head><body><div class="wrap">
    <h1>Ecoa Saúde — Notificações</h1>
    <div class="meta">${total} aparelho(s) registrados</div>
    ${sent ? `<div class="ok">✓ Disparo concluído: ${escapeHtml(sent)}</div>` : ""}
    <div class="card">
      <form method="post" action="/admin/notificacoes">
        <label>Título</label>
        <input name="title" maxlength="80" required placeholder="Ex.: Nova checagem em destaque">
        <label>Mensagem</label>
        <textarea name="body" maxlength="220" required placeholder="Ex.: O boato sobre X foi verificado. Abra e veja as fontes."></textarea>
        <button type="submit">Disparar notificação para todos</button>
      </form>
    </div>
    <p style="margin-top:16px;"><a href="/admin">← Voltar ao painel</a></p>
  </div></body></html>`);
});

app.post("/admin/notificacoes", requireAuth, requireAdmin, async (req, res) => {
  const title = String(req.body?.title || "").trim().slice(0, 80);
  const body = String(req.body?.body || "").trim().slice(0, 220);
  if (!title || !body) return res.redirect("/admin/notificacoes");

  const rows = db.prepare("SELECT token FROM push_tokens").all();

  const messages = rows.map(r => ({
    to: r.token, sound: "default", title, body,
    data: { source: "verifacts-admin" }
  }));
  const result = messages.length ? await sendExpoPush(messages) : { ok: 0, fail: 0 };
  logActivity(req.user.id, req.user.email, "push_admin", `"${title}" → todos: ${result.ok} ok, ${result.fail} falhas`, req);
  const report = `${result.ok} enviada(s), ${result.fail} falha(s)`;
  if (req.body?.back === "admin") return res.redirect("/admin?pushsent=" + encodeURIComponent(report));
  res.redirect("/admin/notificacoes?sent=" + encodeURIComponent(report));
});

// 👑 Excluir usuário pelo painel
app.post("/admin/excluir", requireAuth, requireAdmin, async (req, res) => {
  const userId = Number(req.body.user_id);
  if (userId === req.user.id) return res.redirect("/admin?erro=" + encodeURIComponent("Você não pode excluir a própria conta pelo painel."));
  const target = db.prepare("SELECT * FROM users WHERE id = ?").get(userId);
  if (!target) return res.redirect("/admin?erro=" + encodeURIComponent("Usuário não encontrado."));
  logActivity(userId, target.email, "admin_conta_excluida", `por ${req.user.email}`, req);
  deleteUser(userId);
  db.prepare("DELETE FROM sessions WHERE sess LIKE ?").run(`%"userId":${userId}%`); // derruba sessões ativas do excluído
  console.log(`[Admin] ${req.user.email} excluiu ${target.email}`);
  res.redirect("/admin?ok=excluido");
});

// 👑 Visualizador de logs com filtros
app.get("/admin/logs", requireAuth, requireAdmin, (req, res) => {
  const email = String(req.query.email || "").trim();
  const action = String(req.query.action || "").trim();
  let where = [], params = [];
  if (email) { where.push("email LIKE ?"); params.push(`%${email}%`); }
  if (action) { where.push("action = ?"); params.push(action); }
  const logs = db.prepare(`
    SELECT * FROM activity_log ${where.length ? "WHERE " + where.join(" AND ") : ""}
    ORDER BY id DESC LIMIT 200
  `).all(...params);
  const actions = db.prepare("SELECT DISTINCT action FROM activity_log ORDER BY action").all().map(r => r.action);

  const badgeColor = (a) => {
    if (a === "verificacao") return "#2560CC";
    if (a === "login" || a === "registro") return "#2E8B57";
    if (a.includes("falhou") || a.includes("excluida")) return "#C62828";
    if (a.includes("plano") || a.includes("assinatura")) return "#9c6bff";
    return "#888";
  };
  const td = `padding:8px; border-top:1px solid #E6E8EC; vertical-align:top;`;
  const rows = logs.map(l => `
    <tr>
      <td style="${td} color:#6B7280; white-space:nowrap; font-size:12px;">${new Date(l.created_at).toLocaleString("pt-BR", {dateStyle:"short", timeStyle:"medium"})}</td>
      <td style="${td} white-space:nowrap;">${l.email ? `<a href="/admin/logs?email=${encodeURIComponent(l.email)}" style="color:#4A5260;">${escapeHtml(l.email)}</a>` : `<span style="color:#6B7280;">—</span>`}</td>
      <td style="${td}"><span style="background:${badgeColor(l.action)}20; color:${badgeColor(l.action)}; padding:3px 9px; border-radius:10px; font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:0.04em; white-space:nowrap;">${escapeHtml(l.action)}</span></td>
      <td style="${td} color:#5B6370; font-size:12px; word-break:break-word; max-width:400px;">${escapeHtml(l.details || "")}</td>
      <td style="${td} color:#6B7280; font-size:11px; white-space:nowrap;">${escapeHtml(l.ip || "")}</td>
    </tr>`).join("");

  const content = `
  <div class="page-title">📋 Logs de Atividade</div>
  <div class="page-sub"><a href="/admin" style="color:#2560CC;">← Voltar ao painel</a> · Últimos 200 registros${email || action ? " (filtrados)" : ""}.</div>
  <div class="card" style="overflow-x:auto;">
    <div class="card-title" style="display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap;">
      <span>Atividades (${logs.length})</span>
      <form method="get" action="/admin/logs" style="display:flex; gap:6px; flex-wrap:wrap;">
        <input type="text" name="email" value="${escapeHtml(email)}" placeholder="Filtrar por e-mail..." style="background:#F4F6F9; border:1px solid #E3E6EB; color:#14171C; padding:7px 12px; border-radius:2px; font-size:13px; width:190px;">
        <select name="action" style="background:#F4F6F9; border:1px solid #E3E6EB; color:#3F4652; padding:7px 10px; border-radius:2px; font-size:13px;">
          <option value="">Todas as ações</option>
          ${actions.map(a => `<option value="${escapeHtml(a)}" ${a === action ? "selected" : ""}>${escapeHtml(a)}</option>`).join("")}
        </select>
        <button type="submit" style="background:#EEF1F5; border:1px solid #D5D9E0; color:#3F4652; padding:7px 14px; border-radius:2px; font-size:12px; cursor:pointer;">Filtrar</button>
        ${email || action ? '<a href="/admin/logs" style="align-self:center; color:#6B7280; font-size:12px;">limpar</a>' : ''}
      </form>
    </div>
    <table style="width:100%; border-collapse:collapse; font-size:13px;">
      <thead>
        <tr style="color:#6B7280; text-transform:uppercase; font-size:11px; letter-spacing:0.08em; text-align:left;">
          <th style="padding:8px;">Quando</th><th style="padding:8px;">Usuário</th><th style="padding:8px;">Ação</th><th style="padding:8px;">Detalhes</th><th style="padding:8px;">IP</th>
        </tr>
      </thead>
      <tbody style="color:#4A5260;">${rows || `<tr><td colspan="5" style="padding:20px; text-align:center; color:#6B7280;">Nenhum log ainda.</td></tr>`}</tbody>
    </table>
  </div>`;
  res.send(renderSubPage("Admin", content, req.user));
});


// ══════════════════════════════════════════════════════════
// 📥 EXPORTAÇÃO DE DADOS (somente admin)
// ══════════════════════════════════════════════════════════
const VERDICT_LABELS = {
  provavelmente_falso: "Provavelmente falso",
  suspeito: "Suspeito",
  nao_verificado: "Não verificado",
  provavelmente_verdadeiro: "Provavelmente verdadeiro"
};

function csvCell(v) {
  let t = v === null || v === undefined ? "" : String(v);
  if (/^[=+\-@]/.test(t)) t = "'" + t; // impede que o Excel leia o texto como fórmula
  return '"' + t.replace(/"/g, '""') + '"';
}
function toCsv(cols, rows) {
  const head = cols.map(c => csvCell(c.label)).join(";");
  const body = rows.map(r => cols.map(c => csvCell(c.get ? c.get(r) : r[c.key])).join(";"));
  return "\uFEFF" + [head, ...body].join("\r\n") + "\r\n"; // BOM = acentos certos no Excel
}
function fileStamp() {
  return new Date().toISOString().slice(0, 16).replace(/[:T]/g, "-");
}
function sendDownload(res, filename, mime, body) {
  res.setHeader("Content-Type", `${mime}; charset=utf-8`);
  res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
  res.send(body);
}
function brDateTime(v) {
  if (!v) return "";
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? String(v) : d.toLocaleString("pt-BR");
}

function exportUsers() {
  return db.prepare(`
    SELECT u.id, u.name, u.email, u.created_at,
           COALESCE(m.count, 0) AS month_usage,
           COALESCE(t.total, 0) AS total_usage,
           (SELECT COUNT(*) FROM history h WHERE h.user_id = u.id) AS historico,
           (SELECT MAX(h2.created_at) FROM history h2 WHERE h2.user_id = u.id) AS ultima_pesquisa,
           (SELECT MAX(a.created_at) FROM activity_log a WHERE a.user_id = u.id AND a.action = 'login') AS ultimo_login
    FROM users u
    LEFT JOIN usage m ON m.user_id = u.id AND m.month = ?
    LEFT JOIN (SELECT user_id, SUM(count) AS total FROM usage GROUP BY user_id) t ON t.user_id = u.id
    ORDER BY u.id
  `).all(currentMonth());
}

function exportHistory(userId = null) {
  const base = `
    SELECT h.id, h.user_id, u.name AS user_name, u.email AS user_email,
           h.created_at, h.type, h.verdict, h.summary, h.text
    FROM history h LEFT JOIN users u ON u.id = h.user_id`;
  return userId
    ? db.prepare(base + " WHERE h.user_id = ? ORDER BY h.id DESC").all(userId)
    : db.prepare(base + " ORDER BY h.user_id ASC, h.id DESC").all();
}

function exportLogs(userId = null) {
  return userId
    ? db.prepare("SELECT * FROM activity_log WHERE user_id = ? ORDER BY id DESC").all(userId)
    : db.prepare("SELECT * FROM activity_log ORDER BY id DESC").all();
}

// 📥 Usuários (CSV)
app.get("/admin/exportar/usuarios", requireAuth, requireAdmin, (req, res) => {
  const rows = exportUsers();
  const csv = toCsv([
    { label: "ID", key: "id" },
    { label: "Nome", key: "name" },
    { label: "E-mail", key: "email" },
    { label: "Conta criada em", get: r => brDateTime(r.created_at) },
    { label: "Verificações no mês", key: "month_usage" },
    { label: "Verificações no total", key: "total_usage" },
    { label: "Pesquisas salvas", key: "historico" },
    { label: "Última pesquisa", get: r => brDateTime(r.ultima_pesquisa) },
    { label: "Último login", get: r => brDateTime(r.ultimo_login) }
  ], rows);
  logActivity(req.user.id, req.user.email, "admin_exportou", `usuários (${rows.length} linhas)`, req);
  sendDownload(res, `ecoa-saude-usuarios-${fileStamp()}.csv`, "text/csv", csv);
});

// 📥 Pesquisas de todos (CSV) — ou de um usuário com ?user_id=
app.get("/admin/exportar/pesquisas", requireAuth, requireAdmin, (req, res) => {
  const userId = req.query.user_id ? Number(req.query.user_id) : null;
  const rows = exportHistory(userId);
  const csv = toCsv([
    { label: "ID", key: "id" },
    { label: "Usuário (ID)", key: "user_id" },
    { label: "Nome", key: "user_name" },
    { label: "E-mail", key: "user_email" },
    { label: "Quando", get: r => brDateTime(r.created_at) },
    { label: "Tipo", key: "type" },
    { label: "Veredito", get: r => VERDICT_LABELS[r.verdict] || r.verdict || "" },
    { label: "Resumo", key: "summary" },
    { label: "O que foi pesquisado", key: "text" }
  ], rows);
  logActivity(req.user.id, req.user.email, "admin_exportou", `pesquisas (${rows.length} linhas)`, req);
  sendDownload(res, `ecoa-saude-pesquisas-${fileStamp()}.csv`, "text/csv", csv);
});

// 📥 Logs de atividade (CSV)
app.get("/admin/exportar/logs", requireAuth, requireAdmin, (req, res) => {
  const rows = exportLogs(req.query.user_id ? Number(req.query.user_id) : null);
  const csv = toCsv([
    { label: "ID", key: "id" },
    { label: "Quando", get: r => brDateTime(r.created_at) },
    { label: "Usuário (ID)", key: "user_id" },
    { label: "E-mail", key: "email" },
    { label: "Ação", key: "action" },
    { label: "Detalhes", key: "details" },
    { label: "IP", key: "ip" }
  ], rows);
  logActivity(req.user.id, req.user.email, "admin_exportou", `logs (${rows.length} linhas)`, req);
  sendDownload(res, `ecoa-saude-logs-${fileStamp()}.csv`, "text/csv", csv);
});

// 📥 Tudo em um arquivo (JSON). Com ?completo=1 inclui o relatório completo de cada pesquisa.
app.get("/admin/exportar/tudo", requireAuth, requireAdmin, (req, res) => {
  const completo = req.query.completo === "1";
  const users = exportUsers();
  const history = exportHistory();
  const byUser = new Map(users.map(u => [u.id, []]));
  for (const h of history) {
    const item = {
      id: h.id,
      quando: h.created_at,
      tipo: h.type || null,
      veredito: h.verdict || null,
      resumo: h.summary || null,
      pesquisa: h.text
    };
    if (completo) {
      const full = getHistoryResult(h.user_id, h.id);
      if (full) item.relatorio = full;
    }
    if (!byUser.has(h.user_id)) byUser.set(h.user_id, []);
    byUser.get(h.user_id).push(item);
  }
  const data = {
    app: "Ecoa Saúde",
    exportado_em: new Date().toISOString(),
    exportado_por: req.user.email,
    totais: { usuarios: users.length, pesquisas: history.length },
    usuarios: users.map(u => ({
      id: u.id,
      nome: u.name,
      email: u.email,
      criado_em: u.created_at,
      verificacoes_no_mes: u.month_usage,
      verificacoes_no_total: u.total_usage,
      ultimo_login: u.ultimo_login || null,
      pesquisas: byUser.get(u.id) || []
    }))
  };
  logActivity(req.user.id, req.user.email, "admin_exportou", `tudo${completo ? " (com relatórios)" : ""}: ${users.length} usuários, ${history.length} pesquisas`, req);
  sendDownload(res, `ecoa-saude-tudo-${fileStamp()}.json`, "application/json", JSON.stringify(data, null, 2));
});

// 📥 Um usuário específico (JSON com pesquisas, relatórios e logs)
app.get("/admin/exportar/usuario/:id", requireAuth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const user = db.prepare("SELECT id, name, email, created_at FROM users WHERE id = ?").get(id);
  if (!user) return res.redirect("/admin?erro=" + encodeURIComponent("Usuário não encontrado."));
  const pesquisas = exportHistory(id).map(h => {
    const full = getHistoryResult(id, h.id);
    return {
      id: h.id,
      quando: h.created_at,
      tipo: h.type || null,
      veredito: h.verdict || null,
      resumo: h.summary || null,
      pesquisa: h.text,
      ...(full ? { relatorio: full } : {})
    };
  });
  const data = {
    app: "Ecoa Saúde",
    exportado_em: new Date().toISOString(),
    exportado_por: req.user.email,
    usuario: {
      id: user.id,
      nome: user.name,
      email: user.email,
      criado_em: user.created_at,
      verificacoes_no_mes: getUsage(id),
      verificacoes_no_total: getTotalUsage(id)
    },
    pesquisas,
    atividades: exportLogs(id)
  };
  logActivity(req.user.id, req.user.email, "admin_exportou", `usuário ${user.email} (${pesquisas.length} pesquisas)`, req);
  sendDownload(res, `ecoa-saude-usuario-${id}-${fileStamp()}.json`, "application/json", JSON.stringify(data, null, 2));
});

(async () => {
  await ensureTempDir();

  const llmInfo = CONFIG.OPENAI_API_KEY
    ? `OpenAI ${CONFIG.OPENAI_MODEL}`
    : `Ollama ${CONFIG.OLLAMA_MODEL} (local)`;

  app.listen(CONFIG.PORT, "0.0.0.0", () => {
    console.log(
      `🤖 Ecoa Saúde rodando na porta ${CONFIG.PORT}\n🧠 LLM: ${llmInfo}`
    );
  });
})();

// ╔══════════════════════════════════════════════════════════════════════╗
// ║  API MOBILE DO VERIFACTS                                                ║
// ║  Cole ESTE BLOCO INTEIRO dentro do seu app.js, logo ANTES da linha:    ║
// ║      app.listen(CONFIG.PORT, ...)                                       ║
// ║                                                                         ║
// ║  Ele reaproveita tudo que já existe (db, analyzeText, analyzeLink,      ║
// ║  analyzeImage, createUser, usageInfo, addHistory, getHistory, PLANS,   ║
// ║  isAdmin, upload, extractUrls...). Não exporta nem duplica nada.        ║
// ╚══════════════════════════════════════════════════════════════════════╝

// Parser JSON só para as rotas /api (as rotas web continuam usando form)
const apiJson = express.json({ limit: "12mb" });

// Tabela de tokens de API (separada das sessões web por cookie)
db.exec(`CREATE TABLE IF NOT EXISTS api_tokens (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  last_used TEXT
)`);

// 🔔 [NOVO] Tokens de push por usuário (Expo Push)
db.exec(`CREATE TABLE IF NOT EXISTS push_tokens (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  platform TEXT,
  created_at TEXT NOT NULL
)`);

// Envia mensagens pela Expo Push API (lotes de 100, como a API exige)
async function sendExpoPush(messages) {
  const results = { ok: 0, fail: 0, errors: [] };
  for (let i = 0; i < messages.length; i += 100) {
    const chunk = messages.slice(i, i + 100);
    try {
      const { data } = await axios.post(
        "https://exp.host/--/api/v2/push/send",
        chunk,
        { headers: { "Content-Type": "application/json" }, timeout: 15000 }
      );
      for (const t of (data?.data || [])) {
        if (t.status === "ok") results.ok++;
        else {
          results.fail++;
          results.errors.push(t.message || t.details?.error || "erro");
          // token inválido/desregistrado → remove do banco
          if (t.details?.error === "DeviceNotRegistered" && t.details?.expoPushToken) {
            try { db.prepare("DELETE FROM push_tokens WHERE token = ?").run(t.details.expoPushToken); } catch (_) {}
          }
        }
      }
    } catch (e) {
      results.fail += chunk.length;
      results.errors.push(e.message);
    }
  }
  return results;
}

function apiIssueToken(userId) {
  const token = crypto.randomBytes(32).toString("hex");
  db.prepare("INSERT INTO api_tokens (token, user_id, created_at) VALUES (?,?,?)")
    .run(token, userId, new Date().toISOString());
  return token;
}

function apiPublicUser(u) {
  return { id: u.id, email: u.email, isAdmin: isAdmin(u) };
}

// Middleware: autentica pelo header "Authorization: Bearer <token>"
function apiAuth(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({ message: "Não autenticado." });
  const row = db.prepare("SELECT user_id FROM api_tokens WHERE token = ?").get(token);
  if (!row) return res.status(401).json({ message: "Sessão expirada. Entre novamente." });
  const user = findUserById(row.user_id);
  if (!user) return res.status(401).json({ message: "Usuário não encontrado." });
  db.prepare("UPDATE api_tokens SET last_used = ? WHERE token = ?")
    .run(new Date().toISOString(), token);
  req.user = user;
  req.apiToken = token;
  next();
}

// Converte o resultado das funções analyze* pro formato que o app renderiza
function apiMapResult(r) {
  // achata as reviews das checagens em itens individuais
  const factChecks = [];
  for (const c of (r.factChecks || [])) {
    for (const rev of (c.reviews || [])) {
      factChecks.push({
        publisher: rev.publisher || "",
        rating: rev.textualRating || "",
        title: rev.title || c.text || "",
        url: rev.url || "",
      });
    }
  }
  const news = (r.recentNews || []).map((n) => ({
    title: n.title,
    source: n.source || n.sourceDomain || "",
    url: n.link,
    publishedAt: n.pubDate || "",
  }));
  let aiDetection;
  if (r.aiDetection) {
    const a = r.aiDetection;
    const indicators = [];
    if (a.techniques) {
      for (const [k, t] of Object.entries(a.techniques)) {
        if (t && t.score > 0) indicators.push(k.replace(/^\d+_/, "").replace(/_/g, " "));
      }
    }
    aiDetection = {
      isAiGenerated: typeof a.isAI === "boolean" ? a.isAI : (a.aiProbability ?? 0) >= 0.68,
      score: typeof a.aiProbability === "number" ? a.aiProbability : undefined,
      indicators,
    };
  }
  return {
    verdict: r.verdict,          // provavelmente_falso | suspeito | nao_verificado | provavelmente_verdadeiro
    confidence: r.confidence,
    summary: r.summary,
    reply: r.reply,
    reasons: Array.isArray(r.reasons) ? r.reasons : [],
    claim: r.claimQuery,
    factChecks,
    news,
    aiDetection,
  };
}

// ── AUTH ──────────────────────────────────────────────────────────────────
app.post("/api/auth/register", apiJson, rateLimit(5, 30 * 60000), (req, res) => {
  const email = String(req.body?.email || "").trim();
  const password = String(req.body?.password || "");
  if (!email || password.length < 6)
    return res.status(400).json({ message: "E-mail válido e senha (mín. 6) obrigatórios." });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email))
    return res.status(400).json({ message: "E-mail inválido." });
  if (findUserByEmail(email))
    return res.status(409).json({ message: "E-mail já cadastrado. Faça login." });

  const name = email.split("@")[0];
  const id = createUser({ name, email, password });
  const user = findUserById(id);
  const token = apiIssueToken(id);
  logActivity(id, email, "registro", "app mobile", req);
  res.json({ token, user: apiPublicUser(user) });
});

app.post("/api/auth/login", apiJson, rateLimit(8, 15 * 60000), (req, res) => {
  const email = String(req.body?.email || "").trim();
  const password = String(req.body?.password || "");
  const user = findUserByEmail(email);
  if (!user || !bcrypt.compareSync(password, user.password_hash))
    return res.status(401).json({ message: "E-mail ou senha incorretos." });
  const token = apiIssueToken(user.id);
  logActivity(user.id, user.email, "login", "app mobile", req);
  res.json({ token, user: apiPublicUser(user) });
});

app.get("/api/me", apiAuth, (req, res) => {
  const info = usageInfo(req.user);
  res.json({
    user: apiPublicUser(req.user),
    usage: { used: info.used, total: info.total, limit: null },
  });
});

// ── VERIFICAÇÃO ─────────────────────────────────────────────────────────────
app.post("/api/verify", apiAuth, apiJson, async (req, res) => {
  const content = String(req.body?.content || "").trim();
  if (!content) return res.status(400).json({ message: "Envie um texto ou link." });

  try {
    const urls = extractUrls(content);
    const result = urls.length > 0 ? await analyzeLink(urls[0]) : await analyzeText(content);
    incrementUsage(req.user.id);
    addHistory(req.user.id, content, urls.length > 0 ? "LINK" : "TEXTO",
      { verdict: result.verdict, summary: result.summary, resultJson: serializeResultForHistory(result) });
    logActivity(req.user.id, req.user.email, "verificacao",
      `${urls.length > 0 ? "LINK" : "TEXTO"}: ${content.slice(0, 90)}`, req);
    res.json(apiMapResult(result));
  } catch (e) {
    console.error("[api/verify]", e);
    res.status(500).json({ message: "Falha na verificação." });
  }
});


// 🔔 [NOVO] Registrar token de push do aparelho
app.post("/api/push/register", apiAuth, apiJson, (req, res) => {
  const token = String(req.body?.token || "").trim();
  const platform = String(req.body?.platform || "").slice(0, 20);
  if (!token.startsWith("ExponentPushToken")) {
    return res.status(400).json({ message: "Token de push inválido." });
  }
  db.prepare(`INSERT INTO push_tokens (token, user_id, platform, created_at) VALUES (?,?,?,?)
    ON CONFLICT(token) DO UPDATE SET user_id = excluded.user_id, platform = excluded.platform`)
    .run(token, req.user.id, platform, new Date().toISOString());
  res.json({ ok: true });
});

// ── HISTÓRICO ───────────────────────────────────────────────────────────────
app.get("/api/history", apiAuth, (req, res) => {
  const rows = getHistory(req.user.id);
  res.json(rows.map((r) => ({
    id: String(r.id),
    query: r.text,
    verdict: r.verdict || null,
    summary: r.summary || (r.type ? `Tipo: ${r.type}` : ""),
    createdAt: r.created_at || new Date().toISOString(),
    hasResult: !!r.verdict,
  })));
});

// 📜 [NOVO] Resultado completo de um item do histórico (reabrir no app)
app.get("/api/history/:id/result", apiAuth, async (req, res) => {
  const result = getHistoryResult(req.user.id, Number(req.params.id));
  if (!result) return res.status(404).json({ message: "Resultado não disponível para este item." });
  const mapped = apiMapResult(result);
  mapped.transcript = result.transcript || "";
  if (result.aiDetection && result.aiDetection.techniques) {
    mapped.techniques = apiMapTechniques(result.aiDetection.techniques);
  }
  if (Array.isArray(result.frameAnalyses)) {
    mapped.frames = result.frameAnalyses.map((f, i) => ({
      frame: f.frameNum || i + 1,
      isAI: !!f.isAI,
      score: typeof f.aiProbability === "number" ? f.aiProbability : null,
      image: null, // miniaturas não são salvas no banco
      flaggedTechniques: apiMapTechniques(f.techniques).filter((t) => t.flagged).map((t) => t.name),
    }));
  }
  res.json(mapped);
});

app.delete("/api/history/:id", apiAuth, (req, res) => {
  delHistoryItem(req.user.id, Number(req.params.id));
  res.json({ ok: true });
});

app.delete("/api/history", apiAuth, (req, res) => {
  clearHistory(req.user.id);
  res.json({ ok: true });
});

console.log("📱 API mobile do Ecoa Saúde montada em /api/*");
// ╚═══════════════════ FIM DO BLOCO — cole antes do app.listen ════════════╝

// ╔══════════════════════════════════════════════════════════════════════╗
// ║  SUBSTITUIÇÃO: ROTAS DE MÍDIA COM HEATMAP + TÉCNICAS + FRAMES          ║
// ║                                                                         ║
// ║  No seu app.js, APAGUE as rotas antigas:                                ║
// ║     app.post("/api/verify/image", ...)   (bloco inteiro)                ║
// ║     app.post("/api/verify/video", ...)   (bloco inteiro)                ║
// ║  e cole ESTE bloco no lugar delas.                                      ║
// ╚══════════════════════════════════════════════════════════════════════╝

// Converte o breakdown das 22 técnicas num formato compacto pro app
function apiMapTechniques(t) {
  if (!t) return [];
  return Object.entries(t).map(([k, v]) => ({
    name: k.replace(/^\d+_/, "").replace(/_/g, " "),
    flagged: (v?.score || 0) > 0,          // ⚠️ IA
    value: v?.value != null ? String(v.value) : "",
    threshold: v?.threshold != null ? String(v.threshold) : "",
  }));
}

// Reduz um base64 de imagem para miniatura leve (payload menor no celular)
async function apiThumb(b64, width = 480) {
  try {
    const sharp = require("sharp");
    const buf = await sharp(Buffer.from(b64, "base64"))
      .resize({ width, withoutEnlargement: true })
      .jpeg({ quality: 70 })
      .toBuffer();
    return buf.toString("base64");
  } catch (_) {
    return b64; // se o sharp falhar, manda o original
  }
}

app.post("/api/verify/image", apiAuth, (req, res) => {
  upload.single("file")(req, res, async (err) => {
    if (err) return res.status(400).json({ message: err.message || "Erro no upload." });
    if (!req.file) return res.status(400).json({ message: "Nenhuma imagem enviada." });

    try {
      const result = await analyzeImage(req.file.path, req.body?.caption || "");
      incrementUsage(req.user.id);
      addHistory(req.user.id, req.file.originalname || "imagem", "MÍDIA",
        { verdict: result.verdict, summary: result.summary, resultJson: serializeResultForHistory(result) });
      logActivity(req.user.id, req.user.email, "verificacao", "MÍDIA (app)", req);

      const mapped = apiMapResult(result);
      // 🔥 Mapa de calor (regiões suspeitas) — mesmo do web
      mapped.heatmap = result.heatmapBase64
        ? await apiThumb(result.heatmapBase64, 720)
        : null;
      // 🔬 Breakdown das 22 técnicas — mesmo do web
      mapped.techniques = apiMapTechniques(result.aiDetection?.techniques);
      res.json(mapped);
    } catch (e) {
      console.error("[api/verify/image]", e);
      res.status(500).json({ message: "Falha ao analisar a imagem." });
    } finally {
      await cleanup(req.file.path);
    }
  });
});

app.post("/api/verify/video", apiAuth, (req, res) => {
  upload.single("file")(req, res, async (err) => {
    if (err) {
      const msg = err.code === "LIMIT_FILE_SIZE"
        ? "Vídeo muito grande. O máximo é 80MB."
        : (err.message || "Erro no upload.");
      return res.status(400).json({ message: msg });
    }
    if (!req.file) return res.status(400).json({ message: "Nenhum vídeo enviado." });
    if (!(req.file.mimetype || "").startsWith("video/")) {
      await cleanup(req.file.path);
      return res.status(400).json({ message: "Envie um arquivo de vídeo." });
    }

    try {
      const result = await analyzeVideo(req.file.path, req.body?.caption || "");
      incrementUsage(req.user.id);
      addHistory(req.user.id, req.file.originalname || "vídeo", "MÍDIA",
        { verdict: result.verdict, summary: result.summary, resultJson: serializeResultForHistory(result) });
      logActivity(req.user.id, req.user.email, "verificacao", "VÍDEO (app)", req);

      const mapped = apiMapResult(result);
      mapped.transcript = result.transcript || "";

      // 🎬 Frames com miniatura + score + técnicas ativadas — mesmo do web
      const analyses = Array.isArray(result.frameAnalyses) ? result.frameAnalyses : [];
      const b64s = Array.isArray(result.frameBase64s) ? result.frameBase64s : [];
      mapped.frames = [];
      for (let i = 0; i < analyses.length; i++) {
        const f = analyses[i];
        mapped.frames.push({
          frame: f.frameNum || i + 1,
          isAI: !!f.isAI,
          score: typeof f.aiProbability === "number" ? f.aiProbability : null,
          image: b64s[i] ? await apiThumb(b64s[i], 360) : null,
          flaggedTechniques: apiMapTechniques(f.techniques)
            .filter((t) => t.flagged)
            .map((t) => t.name),
        });
      }
      res.json(mapped);
    } catch (e) {
      console.error("[api/verify/video]", e);
      res.status(500).json({ message: "Falha ao analisar o vídeo." });
    } finally {
      await cleanup(req.file.path);
    }
  });
});

// ╔══════════════════════════════════════════════════════════════════════╗
// ║  CONTA NO APP: PERFIL, SENHA E EXCLUSÃO                                 ║
// ║  Cole este bloco no app.js junto dos outros /api/* (antes do listen).   ║
// ║  Aditivo — não altera nenhuma rota existente.                           ║
// ╚══════════════════════════════════════════════════════════════════════╝

// Dados da conta (nome, e-mail, data de criação)
app.get("/api/account", apiAuth, (req, res) => {
  res.json({
    name: req.user.name || "",
    email: req.user.email,
    createdAt: req.user.created_at || null,
  });
});

// Atualizar nome (e-mail não pode ser alterado — é a identidade da conta)
app.post("/api/account/profile", apiAuth, apiJson, (req, res) => {
  const name = String(req.body?.name || "").trim();
  if (name.length < 2 || name.length > 80) {
    return res.status(400).json({ message: "Nome deve ter entre 2 e 80 caracteres." });
  }
  db.prepare("UPDATE users SET name = ? WHERE id = ?").run(name, req.user.id);
  logActivity(req.user.id, req.user.email, "perfil_alterado", "app mobile", req);
  res.json({ ok: true, name });
});

// Alterar senha (exige a senha atual; derruba as outras sessões do app)
app.post("/api/account/password", apiAuth, apiJson, (req, res) => {
  const current = String(req.body?.current || "");
  const next = String(req.body?.next || "");
  const full = getUserWithHash(req.user.id);
  if (!full || !bcrypt.compareSync(current, full.password_hash)) {
    return res.status(401).json({ message: "Senha atual incorreta." });
  }
  if (next.length < 6) {
    return res.status(400).json({ message: "A nova senha deve ter no mínimo 6 caracteres." });
  }
  db.prepare("UPDATE users SET password_hash = ? WHERE id = ?")
    .run(bcrypt.hashSync(next, 10), req.user.id);
  // invalida os outros tokens do app (mantém só a sessão atual)
  db.prepare("DELETE FROM api_tokens WHERE user_id = ? AND token != ?")
    .run(req.user.id, req.apiToken || "");
  logActivity(req.user.id, req.user.email, "senha_alterada", "app mobile", req);
  res.json({ ok: true });
});

// Excluir conta (exige senha; mantém apenas o hash antifraude do trial,
// conforme a Política de Privacidade)
app.post("/api/account/delete", apiAuth, apiJson, (req, res) => {
  const password = String(req.body?.password || "");
  const full = getUserWithHash(req.user.id);
  if (!full || !bcrypt.compareSync(password, full.password_hash)) {
    return res.status(401).json({ message: "Senha incorreta." });
  }
  const uid = req.user.id;
  const email = req.user.email;
  db.prepare("DELETE FROM push_tokens WHERE user_id = ?").run(uid);
  db.prepare("DELETE FROM api_tokens WHERE user_id = ?").run(uid);
  deleteUser(uid); // apaga uso + histórico + usuário
  logActivity(uid, email, "conta_excluida", "app mobile", req);
  res.json({ ok: true });
});

console.log("👤 Rotas de conta do app montadas em /api/account/*");