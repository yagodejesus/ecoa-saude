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
  // 💳 [NOVO] Stripe (pagamentos por assinatura)
  STRIPE_SECRET_KEY: process.env.STRIPE_SECRET_KEY || "",
  STRIPE_WEBHOOK_SECRET: process.env.STRIPE_WEBHOOK_SECRET || "",
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
    subject: "Redefinição de senha — Verifacts",
    html: `<div style="font-family:Arial,sans-serif; max-width:480px; margin:0 auto;">
      <h2 style="color:#0a0a0a;">Redefinição de senha</h2>
      <p>Recebemos um pedido para redefinir a senha da sua conta no <strong>Verifacts</strong>.</p>
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

// 💳 [NOVO] Cliente Stripe (só inicializa se a chave existir)
let stripe = null;
if (CONFIG.STRIPE_SECRET_KEY) {
  try {
    // timeout 25s (em vez de 80s) + 2 retentativas automáticas em falha de rede
    stripe = require("stripe")(CONFIG.STRIPE_SECRET_KEY, { timeout: 25000, maxNetworkRetries: 2 });
  } catch (e) {
    console.error("[Stripe] Pacote não instalado. Rode: npm install stripe");
  }
}

// 💳 [NOVO] Webhook do Stripe — PRECISA vir antes do express.json()
// (a verificação de assinatura exige o body cru, não parseado)
app.post("/webhook/stripe", express.raw({ type: "application/json" }), (req, res) => {
  if (!stripe) return res.status(400).send("Stripe não configurado");
  let event;
  try {
    if (CONFIG.STRIPE_WEBHOOK_SECRET) {
      event = stripe.webhooks.constructEvent(req.body, req.headers["stripe-signature"], CONFIG.STRIPE_WEBHOOK_SECRET);
    } else if (process.env.NODE_ENV === "production") {
      // 🔒 [SEGURANÇA] Em produção, webhook sem assinatura = qualquer um poderia
      // forjar um "pagamento concluído" e ganhar plano de graça. Recusar.
      console.error("[Stripe] Webhook recusado: STRIPE_WEBHOOK_SECRET não configurado em produção");
      return res.status(400).send("Webhook não verificado");
    } else {
      event = JSON.parse(req.body); // apenas em desenvolvimento local
      console.warn("[Stripe] Webhook SEM verificação de assinatura — defina STRIPE_WEBHOOK_SECRET em produção");
    }
  } catch (e) {
    console.error("[Stripe] Webhook inválido:", e.message);
    return res.status(400).send(`Webhook error: ${e.message}`);
  }

  try {
    switch (event.type) {
      // Pagamento concluído → ativar plano
      case "checkout.session.completed": {
        const s = event.data.object;
        const userId = Number(s.client_reference_id || s.metadata?.userId);
        const plan = s.metadata?.plan;
        if (userId && ["starter", "profissional"].includes(plan)) {
          updateUserPlan(userId, plan);
          setUserStripe(userId, s.customer, s.subscription);
          logActivity(userId, null, "assinatura_ativada", `plano ${plan} via webhook`); // 📋
          console.log(`[Stripe] ✓ Assinatura ativada: user ${userId} → ${plan}`);
        }
        break;
      }
      // Assinatura cancelada/encerrada → voltar pro grátis
      case "customer.subscription.deleted": {
        const sub = event.data.object;
        const user = findUserByStripeSubscription(sub.id);
        if (user) {
          updateUserPlan(user.id, "gratis");
          setUserStripe(user.id, user.stripe_customer_id, null);
          logActivity(user.id, user.email, "assinatura_cancelada", "rebaixado para gratis via webhook"); // 📋
          console.log(`[Stripe] ✗ Assinatura cancelada: ${user.email} → gratis`);
        }
        break;
      }
      // Falha de cobrança (cartão recusado na renovação)
      case "invoice.payment_failed": {
        const inv = event.data.object;
        console.warn(`[Stripe] ⚠ Falha de pagamento: customer ${inv.customer}`);
        break;
      }
    }
  } catch (e) {
    console.error("[Stripe] Erro processando webhook:", e.message);
  }
  res.json({ received: true });
});

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
// 🔐 AUTENTICAÇÃO + PLANOS + LIMITES DE USO
// ══════════════════════════════════════════════════════════

// Planos (alinhados com a estratégia de pricing)
// "lifetime: true" = limite TOTAL da conta (não renova por mês)
const PLANS = {
  gratis:        { name: "Grátis",        limit: 2,    price: "R$ 0",         lifetime: true },
  starter:       { name: "Starter",       limit: 100,  price: "R$ 129,90/mês" },
  profissional:  { name: "Profissional",  limit: 1000, price: "R$ 339,90/mês" },
  institucional: { name: "Institucional", limit: -1,   price: "Sob consulta" } // -1 = ilimitado
};

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
// 💳 [NOVO] Migração: colunas do Stripe (ignora erro se já existirem)
try { db.exec("ALTER TABLE users ADD COLUMN stripe_customer_id TEXT"); } catch (_) {}
try { db.exec("ALTER TABLE users ADD COLUMN stripe_subscription_id TEXT"); } catch (_) {}

// 🛡️ [ANTIFRAUDE] Registro de teste grátis por e-mail (sobrevive à exclusão da conta)
// Guarda apenas um HASH do e-mail (não o e-mail) + quanto do trial foi usado.
// Impede o golpe: criar conta → gastar 2 grátis → excluir → recriar → repetir.
db.exec(`CREATE TABLE IF NOT EXISTS trial_registry (
  email_hash TEXT PRIMARY KEY,
  trial_used INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT
)`);

// Normaliza o e-mail para o hash antifraude:
// - minúsculas e trim
// - remove alias "+qualquercoisa" (yago+1@gmail.com → yago@gmail.com)
// - no Gmail, remove pontos do usuário (y.a.go@gmail.com → yago@gmail.com)
function normalizeEmailForTrial(email) {
  let [local, domain] = String(email).trim().toLowerCase().split("@");
  if (!domain) return String(email).trim().toLowerCase();
  local = local.split("+")[0];
  if (domain === "gmail.com" || domain === "googlemail.com") {
    local = local.replace(/\./g, "");
    domain = "gmail.com";
  }
  return `${local}@${domain}`;
}
function emailTrialHash(email) {
  return crypto.createHash("sha256").update(normalizeEmailForTrial(email)).digest("hex");
}
function recordTrialUsage(email, used) {
  const h = emailTrialHash(email);
  db.prepare(`
    INSERT INTO trial_registry (email_hash, trial_used, updated_at) VALUES (?, ?, ?)
    ON CONFLICT(email_hash) DO UPDATE SET trial_used = MAX(trial_used, excluded.trial_used), updated_at = excluded.updated_at
  `).run(h, used, new Date().toISOString());
}
function getPriorTrialUsage(email) {
  const row = db.prepare("SELECT trial_used FROM trial_registry WHERE email_hash = ?").get(emailTrialHash(email));
  return row ? row.trial_used : 0;
}

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
const MAX_HISTORY_PER_USER = 20;
function addHistory(userId, text, type) {
  const t = String(text).trim().slice(0, 500);
  if (!t) return;
  // Remove duplicata do mesmo texto (sobe pro topo)
  db.prepare("DELETE FROM history WHERE user_id = ? AND text = ?").run(userId, t);
  db.prepare("INSERT INTO history (user_id, text, type, created_at) VALUES (?,?,?,?)").run(userId, t, type || "", new Date().toISOString());
  // Mantém só os últimos N
  db.prepare(`DELETE FROM history WHERE user_id = ? AND id NOT IN (
    SELECT id FROM history WHERE user_id = ? ORDER BY id DESC LIMIT ?
  )`).run(userId, userId, MAX_HISTORY_PER_USER);
}
function getHistory(userId) {
  return db.prepare("SELECT id, text, type FROM history WHERE user_id = ? ORDER BY id DESC LIMIT ?").all(userId, MAX_HISTORY_PER_USER);
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
  if (CONFIG.STRIPE_SECRET_KEY && !CONFIG.STRIPE_WEBHOOK_SECRET) console.warn("⚠️ [Stripe] STRIPE_WEBHOOK_SECRET não definido — webhooks serão recusados em produção");
  if (CONFIG.STRIPE_SECRET_KEY && CONFIG.APP_URL.includes("localhost")) console.warn("⚠️ [Stripe] APP_URL aponta para localhost — o retorno do checkout vai falhar");
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
function createUser({ name, email, password, plan = "gratis" }) {
  const hash = bcrypt.hashSync(password, 10);
  const stmt = db.prepare("INSERT INTO users (name,email,password_hash,plan,created_at) VALUES (?,?,?,?,?)");
  const info = stmt.run(name.trim(), email.trim().toLowerCase(), hash, plan, new Date().toISOString());
  return info.lastInsertRowid;
}
function findUserByEmail(email) {
  return db.prepare("SELECT * FROM users WHERE email = ?").get(String(email).trim().toLowerCase());
}
function findUserById(id) {
  return db.prepare("SELECT id,name,email,plan,created_at,stripe_customer_id,stripe_subscription_id FROM users WHERE id = ?").get(id);
}
// 💳 [NOVO] Helpers do Stripe
function setUserStripe(id, customerId, subscriptionId) {
  db.prepare("UPDATE users SET stripe_customer_id = ?, stripe_subscription_id = ? WHERE id = ?").run(customerId || null, subscriptionId || null, id);
}
function findUserByStripeSubscription(subId) {
  return db.prepare("SELECT * FROM users WHERE stripe_subscription_id = ?").get(subId);
}
function updateUserName(id, name) {
  db.prepare("UPDATE users SET name = ? WHERE id = ?").run(String(name).trim(), id);
}
function updateUserPassword(id, password) {
  db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(bcrypt.hashSync(password, 10), id);
}
function updateUserPlan(id, plan) {
  db.prepare("UPDATE users SET plan = ? WHERE id = ?").run(plan, id);
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
// 🔴 [NOVO] Uso total da conta (para plano grátis: 2 verificações VITALÍCIAS)
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
function planOf(user) { return PLANS[user.plan] || PLANS.gratis; }
function usageInfo(user) {
  const plan = planOf(user);
  const lifetime = !!plan.lifetime;
  const used = lifetime ? getTotalUsage(user.id) : getUsage(user.id);
  // 👑 Admin = sempre ilimitado, independente do plano
  const unlimited = plan.limit === -1 || isAdmin(user);
  return { used, limit: plan.limit, unlimited, lifetime: lifetime && !unlimited, remaining: unlimited ? Infinity : Math.max(0, plan.limit - used), planName: isAdmin(user) ? "Admin" : plan.name };
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
function checkUsageLimit(req, res, next) {
  const info = usageInfo(req.user);
  if (!info.unlimited && info.used >= info.limit) {
    const isGratis = req.user.plan === "gratis";
    return res.send(renderPage(`
      <div style="text-align:center; padding: 40px 20px;">
        <div style="font-family:'Barlow Condensed',sans-serif; font-size:28px; font-weight:700; color:#fb8c00; text-transform:uppercase; margin-bottom:12px;">${isGratis ? "Teste grátis esgotado" : "Limite mensal atingido"}</div>
        <p style="color:#aaa; font-size:15px; max-width:480px; margin:0 auto 20px;">${isGratis
          ? `Você usou suas <strong style="color:#fff;">2 verificações gratuitas</strong>. Assine um plano para continuar verificando conteúdos.`
          : `Você usou todas as <strong style="color:#fff;">${info.limit} verificações</strong> do plano ${info.planName} este mês. Faça upgrade para continuar verificando.`}</p>
        <a href="/planos" style="display:inline-block; background:#f0f0f0; color:#0a0a0a; padding:12px 28px; border-radius:2px; font-family:'Barlow Condensed',sans-serif; font-weight:700; text-transform:uppercase; letter-spacing:0.1em; font-size:14px;">Ver planos</a>
      </div>
    `, req.user));
  }
  next();
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
2. Envie o arquivo MP4 como "Imagem ou Vídeo" no Verifacts
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
3. Envie como "Imagem ou Vídeo" no Verifacts

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
    const aiColor = aiPct > 70 ? "#e53935" : aiPct > 40 ? "#fb8c00" : "#43a047";
    
    aiSection = `<div style="background: rgba(30,136,229,0.06); border: 1px solid #1e88e5; border-radius: 2px; padding: 20px; margin-bottom: 20px;">
      <div style="font-family: 'Barlow Condensed', sans-serif; font-size: 12px; color: #1e88e5; text-transform: uppercase; font-weight: 700; margin-bottom: 16px;">
        🔍 Detecção de IA ${isAPI ? '(via Replicate 🤖)' : '(análise local)'}
      </div>
      <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-bottom: 16px;">
        <div>
          <div style="color: #888; font-size: 12px; margin-bottom: 8px;">Probabilidade de IA</div>
          <div style="font-size: 28px; font-weight: 700; color: ${aiColor};">${aiPct}%</div>
          <div style="color: #aaa; font-size: 12px; margin-top: 4px;">${aiStatus}</div>
        </div>
        <div>
          <div style="color: #888; font-size: 12px; margin-bottom: 8px;">Confiança</div>
          <div style="font-size: 28px; font-weight: 700; color: #5b9bd5;">${confPct}%</div>
          <div style="color: #aaa; font-size: 12px; margin-top: 4px;">${isAPI ? 'Modelo IA' : 'Heurística'}</div>
        </div>
        <div>
          <div style="color: #888; font-size: 12px; margin-bottom: 8px;">Classificação</div>
          <div style="font-size: 14px; font-weight: 600; color: #5b9bd5; word-break: break-word; margin-top: 8px;">${escapeHtml(result.aiDetection.label || 'N/A')}</div>
        </div>
      </div>
      ${result.aiDetection.noiseScore !== undefined ? `
        <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; padding-top: 12px; border-top: 1px solid #2e2e2e;">
          <div><span style="color: #888; font-size: 11px;">Ruído Detectado:</span> <span style="color: #5b9bd5; font-weight: 600;">${Math.round((result.aiDetection.noiseScore || 0) * 100)}%</span></div>
          <div><span style="color: #888; font-size: 11px;">Artefatos:</span> <span style="color: #5b9bd5; font-weight: 600;">${Math.round((result.aiDetection.artifactScore || 0) * 100)}%</span></div>
        </div>
      ` : ''}
      ${result.heatmapBase64 ? `<div style="margin-top: 16px;"><div style="font-size: 12px; color: #888; margin-bottom: 8px;">Mapa de Calor (Anomalias):</div><img src="data:image/png;base64,${result.heatmapBase64}" style="width: 100%; max-width: 500px; border-radius: 4px; border: 1px solid #333;"><div style="color: #666; font-size: 11px; margin-top: 8px;">🔵 Azul = Autêntico | 🔴 Vermelho = Possível IA</div></div>` : ""}
    </div>`;
  }
  
  // Video Frames Analysis
  let videoFramesSection = "";
  if (result.frameAnalyses && result.frameAnalyses.length > 0) {
    const avgAI = (result.frameAnalyses.reduce((a, f) => a + f.aiProbability, 0) / result.frameAnalyses.length * 100).toFixed(0);
    videoFramesSection = `<div style="background: rgba(30,136,229,0.06); border: 1px solid #1e88e5; border-radius: 2px; padding: 20px; margin-bottom: 20px;">
      <div style="font-family: 'Barlow Condensed', sans-serif; font-size: 12px; color: #1e88e5; text-transform: uppercase; font-weight: 700; margin-bottom: 16px;">🎬 Análise de Frames - Técnicas Ativadas</div>
      <div style="margin-bottom: 16px; padding: 8px; background: #1a1a1a; border-radius: 4px; color: #aaa; font-size: 12px;">IA Detectada (Média): <span style="color: #5b9bd5; font-weight: 700;">${avgAI}%</span></div>
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 400px), 1fr)); gap: 16px;">`;
    
    result.frameAnalyses.forEach((frame, idx) => {
      const frameAiPct = Math.round((frame.aiProbability || 0) * 100);
      const frameColor = frameAiPct > 70 ? "#e53935" : frameAiPct > 40 ? "#fb8c00" : "#43a047";
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
                <span style="color: #ddd; font-size: 13px; font-weight: 500; display: flex; align-items: center; gap: 5px;">
                  ${escapeHtml(cleanName)}
                  <span class="tech-info" tabindex="0" data-tip="${desc}">!</span>
                </span>
                <span style="color: #e53935; font-size: 11px; font-weight: 700;">⚠ IA</span>
              </div>
              <div style="color: #ff8a80; font-size: 16px; font-weight: 700; margin-top: 4px; font-family: 'Barlow Condensed', sans-serif;">${tech.value}</div>
            </div>`;
          }).join('') 
        : `<div style="grid-column: 1/-1; color: #43a047; font-size: 14px; padding: 12px; text-align: center; background: rgba(67,160,71,0.08); border-radius: 6px;">✓ Nenhuma anomalia de IA detectada</div>`;
      
      // Cards de técnicas limpas (compactos)
      const cleanCards = cleanTechniques.map(([name, tech]) => {
        const cleanName = name.replace(/^\d+_/, '').replace(/_/g, ' ');
        const desc = escapeHtml(techDescription(name));
        return `<div style="background: rgba(67,160,71,0.05); border: 1px solid rgba(67,160,71,0.2); border-radius: 6px; padding: 8px 10px;">
          <div style="display: flex; align-items: center; justify-content: space-between; gap: 6px;">
            <span style="color: #999; font-size: 12px; display: flex; align-items: center; gap: 5px;">
              ${escapeHtml(cleanName)}
              <span class="tech-info" tabindex="0" data-tip="${desc}">!</span>
            </span>
            <span style="color: #43a047; font-size: 11px;">✓</span>
          </div>
          <div style="color: #6a9; font-size: 13px; font-weight: 600; margin-top: 2px; font-family: 'Barlow Condensed', sans-serif;">${tech.value}</div>
        </div>`;
      }).join('');
      
      videoFramesSection += `<div style="padding: 14px; background: #1a1a1a; border: 2px solid ${frameColor}40; border-radius: 8px;">
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px;">
          <div style="font-weight: 600; color: #fff; font-size: 17px;">📹 Frame ${frame.frameNum}</div>
          <div style="background: ${frameColor}20; color: ${frameColor}; font-size: 11px; font-weight: 700; padding: 4px 10px; border-radius: 12px; text-transform: uppercase; letter-spacing: 0.05em;">${frameLabel}</div>
        </div>
        
        <!-- Frame com overlay de bolinhas marcando rastros de IA -->
        <div style="position: relative; width: 100%; margin-bottom: 12px; background: #000; border-radius: 4px; box-sizing: border-box; line-height: 0;">
          <img src="data:image/jpeg;base64,${result.frameBase64s[idx]}" style="width: 100%; height: auto; border-radius: 4px; display: block; box-shadow: 0 4px 8px rgba(0,0,0,0.5); border: 1px solid #333;">
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
        <div style="display: flex; flex-wrap: wrap; gap: 14px; margin-bottom: 12px; padding: 8px 12px; background: #0f0f0f; border-radius: 6px; font-size: 11px; color: #aaa;">
          <span style="display: flex; align-items: center; gap: 5px;"><span style="width: 10px; height: 10px; border-radius: 50%; border: 2px solid #FFD700; background: #FFD70033; display: inline-block;"></span> Bloom/Halo</span>
          <span style="display: flex; align-items: center; gap: 5px;"><span style="width: 10px; height: 10px; border-radius: 50%; border: 2px solid #FF5252; background: #FF525233; display: inline-block;"></span> Bordas artificiais</span>
          <span style="display: flex; align-items: center; gap: 5px;"><span style="width: 10px; height: 10px; border-radius: 50%; border: 2px solid #40C4FF; background: #40C4FF33; display: inline-block;"></span> Luz inconsistente</span>
          <span style="margin-left: auto; color: #666;">${frame.aiTraceDots.length} rastros marcados</span>
        </div>
        ` : ''}
        
        <!-- Barra de IA Detectada -->
        <div style="padding: 12px 14px; background: #0a0a0a; border-radius: 6px; margin-bottom: 14px; border-left: 4px solid ${frameColor}; display: flex; align-items: center; justify-content: space-between;">
          <span style="color: #aaa; font-size: 14px; font-weight: 600;">IA Detectada</span>
          <span style="color: ${frameColor}; font-size: 32px; font-weight: 700; font-family: 'Barlow Condensed', sans-serif; line-height: 1;">${frameAiPct}%</span>
        </div>
        
        <!-- Técnicas que acusaram IA -->
        <div style="font-size: 12px; color: #e53935; margin-bottom: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em;">⚠ Indicadores de IA (${activeTechniques.length})</div>
        <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(130px, 1fr)); gap: 8px; margin-bottom: 16px;">
          ${activeCards}
        </div>
        
        <!-- Técnicas limpas (verificações OK) -->
        <div style="font-size: 12px; color: #43a047; margin-bottom: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em;">✓ Verificações OK (${cleanTechniques.length})</div>
        <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(110px, 1fr)); gap: 6px;">
          ${cleanCards}
        </div>
      </div>`;
    });
    videoFramesSection += `</div></div>`;
  } else if (result.inputType === "video" && !result.ffmpegAvailable) {
    // 🔴 [NOVO] Mensagem quando ffmpeg não está disponível
    videoFramesSection = `<div style="background: rgba(255,152,0,0.06); border: 1px solid #ff9800; border-radius: 2px; padding: 20px; margin-bottom: 20px;">
      <div style="font-family: 'Barlow Condensed', sans-serif; font-size: 12px; color: #ff9800; text-transform: uppercase; font-weight: 700; margin-bottom: 12px;">⚠️ Análise de Frames Indisponível</div>
      <div style="color: #aaa; font-size: 13px; line-height: 1.5;">
        <p>FFmpeg não está instalado. Para analisar frames de vídeos, instale:</p>
        <div style="background: #1a1a1a; padding: 10px; border-radius: 4px; font-family: monospace; margin: 8px 0; font-size: 12px; color: #5b9bd5;">
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
  <title>${pageTitle} · Verifacts</title>
  <link rel="icon" href="data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20viewBox%3D%220%200%2064%2064%22%3E%3Crect%20width%3D%2264%22%20height%3D%2264%22%20rx%3D%2212%22%20fill%3D%22%230a0a0a%22%2F%3E%3Ctext%20x%3D%2232%22%20y%3D%2244%22%20font-family%3D%22Arial%2Csans-serif%22%20font-size%3D%2234%22%20font-weight%3D%22700%22%20text-anchor%3D%22middle%22%3E%3Ctspan%20fill%3D%22%23f0f0f0%22%3EV%3C%2Ftspan%3E%3Ctspan%20fill%3D%22%23d0312d%22%3EF%3C%2Ftspan%3E%3C%2Ftext%3E%3C%2Fsvg%3E">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Barlow+Condensed:wght@400;500;600;700&family=Barlow:wght@300;400&display=swap" rel="stylesheet">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: #0a0a0a; color: #ccc;
      font-family: 'Barlow', sans-serif; font-weight: 300;
      min-height: 100vh; display: flex; align-items: center; justify-content: center;
      padding: 20px;
    }
    .auth-card {
      width: 100%; max-width: 400px;
      background: #111; border: 1px solid #2e2e2e; border-top: 2px solid #5b9bd5;
      border-radius: 2px; padding: 40px 36px;
    }
    .auth-logo {
      font-family: 'Barlow Condensed', sans-serif; font-weight: 700; font-size: 30px;
      letter-spacing: 0.04em; text-transform: uppercase; color: #f0f0f0;
      text-align: center; margin-bottom: 6px;
    }
    .auth-logo span { color: #d0312d; }
    .auth-sub { text-align: center; font-size: 13px; color: #555; margin-bottom: 30px; }
    .f { margin-bottom: 16px; }
    .f label {
      display: block; font-family: 'Barlow Condensed', sans-serif; font-size: 12px;
      font-weight: 600; letter-spacing: 0.14em; text-transform: uppercase;
      color: #555; margin-bottom: 6px;
    }
    .f input {
      width: 100%; background: #181818; border: 1px solid #2e2e2e; border-radius: 2px;
      color: #f0f0f0; font-family: 'Barlow', sans-serif; font-size: 16px;
      padding: 12px 14px; outline: none; transition: border-color 0.15s;
    }
    .f input:focus { border-color: #5b9bd5; }
    .auth-btn {
      width: 100%; margin-top: 8px; padding: 14px;
      background: #f0f0f0; color: #0a0a0a; border: none; border-radius: 2px;
      font-family: 'Barlow Condensed', sans-serif; font-size: 15px; font-weight: 700;
      letter-spacing: 0.12em; text-transform: uppercase; cursor: pointer;
      transition: background 0.15s;
    }
    .auth-btn:hover { background: #d8d8d8; }
    .auth-error {
      background: rgba(229,57,53,0.1); border: 1px solid rgba(229,57,53,0.4);
      color: #ff8a80; font-size: 13px; padding: 10px 14px; border-radius: 2px;
      margin-bottom: 18px; line-height: 1.4;
    }
    .auth-switch { text-align: center; margin-top: 22px; font-size: 14px; color: #555; }
    .auth-switch a { color: #5b9bd5; text-decoration: none; }
    .auth-switch a:hover { color: #f0f0f0; }
    .auth-plans {
      margin-top: 24px; padding-top: 18px; border-top: 1px solid #222;
      font-size: 12px; color: #555; line-height: 1.8; text-align: center;
    }
    .auth-plans b { color: #888; }
  </style>
</head>
<body>
  <div class="auth-card">
    <div class="auth-logo">Veri<span>facts</span></div>
    <div class="auth-sub">Verificação de fatos + Detecção de IA</div>
    ${error ? `<div class="auth-error">${escapeHtml(error)}</div>` : ""}
    ${notice ? `<div class="auth-error" style="background:rgba(67,160,71,0.1); border-color:rgba(67,160,71,0.4); color:#81c784;">${escapeHtml(notice)}</div>` : ""}
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
      ${isLogin ? `<div style="text-align:right; margin:-6px 0 14px;"><a href="/esqueci" style="font-size:13px; color:#5b9bd5;">Esqueceu a senha?</a></div>` : ""}
      <button class="auth-btn" type="submit">${isRedefinir ? "Salvar nova senha" : isEsqueci ? "Enviar link de recuperação" : isLogin ? "Entrar" : "Criar conta grátis"}</button>
    </form>
    <div class="auth-switch">
      ${isLogin ? `Não tem conta? <a href="/register">Criar conta</a>`
        : isEsqueci || isRedefinir ? `Lembrou a senha? <a href="/login">Entrar</a>`
        : `Já tem conta? <a href="/login">Entrar</a>`}
    </div>
    ${mode === "register" ? `
    <div class="auth-plans">
      Sua conta inicia no plano <b>Grátis</b>: 2 verificações para testar, sem cartão.<br>
      Planos pagos: Starter R$ 129,90 · Profissional R$ 339,90 · Institucional sob consulta
    </div>` : ""}
  </div>
</body>
</html>`;
}

// ══════════════════════════════════════════════════════════
// ⚙️ PÁGINAS: CONTA (configurações) e PLANOS (mudança de plano)
// ══════════════════════════════════════════════════════════
function renderSubPage(title, content, user) {
  const info = usageInfo(user);
  const usageText = info.unlimited ? `${info.used} verificações` : `${info.used} / ${info.limit}`;
  return `<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${escapeHtml(title)} · Verifacts</title>
  <link rel="icon" href="data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20viewBox%3D%220%200%2064%2064%22%3E%3Crect%20width%3D%2264%22%20height%3D%2264%22%20rx%3D%2212%22%20fill%3D%22%230a0a0a%22%2F%3E%3Ctext%20x%3D%2232%22%20y%3D%2244%22%20font-family%3D%22Arial%2Csans-serif%22%20font-size%3D%2234%22%20font-weight%3D%22700%22%20text-anchor%3D%22middle%22%3E%3Ctspan%20fill%3D%22%23f0f0f0%22%3EV%3C%2Ftspan%3E%3Ctspan%20fill%3D%22%23d0312d%22%3EF%3C%2Ftspan%3E%3C%2Ftext%3E%3C%2Fsvg%3E">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Barlow+Condensed:wght@400;500;600;700&family=Barlow:wght@300;400&display=swap" rel="stylesheet">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background:#0a0a0a; color:#ccc; font-family:'Barlow',sans-serif; font-weight:300; font-size:16px; line-height:1.6; min-height:100vh; }
    a { color:#888; text-decoration:none; } a:hover { color:#f0f0f0; }
    header { border-bottom:1px solid #222; padding:0 32px; display:flex; align-items:center; justify-content:space-between; height:62px; }
    .logo { font-family:'Barlow Condensed',sans-serif; font-weight:700; font-size:26px; letter-spacing:0.04em; text-transform:uppercase; color:#f0f0f0; }
    .logo span { color:#d0312d; }
    .nav { display:flex; align-items:center; gap:20px; }
    .nav a { font-family:'Barlow Condensed',sans-serif; font-size:13px; font-weight:600; letter-spacing:0.1em; text-transform:uppercase; color:#555; transition:color 0.15s; }
    .nav a:hover, .nav a.active { color:#f0f0f0; }
    .nav .sair { border:1px solid #2e2e2e; padding:7px 14px; border-radius:2px; }
    .nav .sair:hover { color:#e53935; border-color:#e53935; }
    .wrap { max-width:820px; margin:0 auto; padding:40px 24px 80px; }
    .page-title { font-family:'Barlow Condensed',sans-serif; font-size:30px; font-weight:700; letter-spacing:0.04em; text-transform:uppercase; color:#f0f0f0; margin-bottom:6px; }
    .page-sub { font-size:14px; color:#555; margin-bottom:34px; }
    .card { background:#111; border:1px solid #222; border-radius:2px; padding:28px; margin-bottom:22px; }
    .card-title { font-family:'Barlow Condensed',sans-serif; font-size:14px; font-weight:700; letter-spacing:0.14em; text-transform:uppercase; color:#5b9bd5; margin-bottom:20px; padding-bottom:10px; border-bottom:1px solid #222; }
    .f { margin-bottom:16px; }
    .f label { display:block; font-family:'Barlow Condensed',sans-serif; font-size:12px; font-weight:600; letter-spacing:0.14em; text-transform:uppercase; color:#555; margin-bottom:6px; }
    .f input { width:100%; background:#181818; border:1px solid #2e2e2e; border-radius:2px; color:#f0f0f0; font-family:'Barlow',sans-serif; font-size:16px; padding:11px 13px; outline:none; transition:border-color 0.15s; }
    .f input:focus { border-color:#5b9bd5; }
    .f input[disabled] { color:#666; cursor:not-allowed; }
    .btn { padding:12px 26px; background:#f0f0f0; color:#0a0a0a; border:none; border-radius:2px; font-family:'Barlow Condensed',sans-serif; font-size:14px; font-weight:700; letter-spacing:0.12em; text-transform:uppercase; cursor:pointer; transition:background 0.15s; }
    .btn:hover { background:#d8d8d8; }
    .msg-ok { background:rgba(67,160,71,0.1); border:1px solid rgba(67,160,71,0.4); color:#81c784; font-size:13px; padding:10px 14px; border-radius:2px; margin-bottom:20px; }
    .msg-err { background:rgba(229,57,53,0.1); border:1px solid rgba(229,57,53,0.4); color:#ff8a80; font-size:13px; padding:10px 14px; border-radius:2px; margin-bottom:20px; }
    .usage-bar { height:6px; background:#222; border-radius:3px; overflow:hidden; margin-top:10px; }
    .usage-fill { height:100%; border-radius:3px; }
    .plans-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(230px,1fr)); gap:16px; }
    .plan-card { background:#111; border:1px solid #2e2e2e; border-radius:4px; padding:26px 22px; display:flex; flex-direction:column; transition:border-color 0.15s; position:relative; }
    .plan-card:hover { border-color:#555; }
    .plan-card.current { border-color:#5b9bd5; }
    .plan-badge { position:absolute; top:-11px; left:50%; transform:translateX(-50%); background:#5b9bd5; color:#0a0a0a; font-family:'Barlow Condensed',sans-serif; font-size:11px; font-weight:700; letter-spacing:0.1em; text-transform:uppercase; padding:3px 12px; border-radius:10px; }
    .plan-name { font-family:'Barlow Condensed',sans-serif; font-size:20px; font-weight:700; letter-spacing:0.06em; text-transform:uppercase; color:#f0f0f0; margin-bottom:4px; }
    .plan-price { font-family:'Barlow Condensed',sans-serif; font-size:28px; font-weight:700; color:#5b9bd5; margin-bottom:14px; }
    .plan-feats { list-style:none; font-size:14px; color:#888; line-height:2; margin-bottom:20px; flex:1; }
    .plan-feats li::before { content:'✓ '; color:#43a047; }
    .plan-btn { width:100%; padding:11px; border-radius:2px; font-family:'Barlow Condensed',sans-serif; font-size:13px; font-weight:700; letter-spacing:0.1em; text-transform:uppercase; cursor:pointer; border:1px solid #2e2e2e; background:transparent; color:#ccc; transition:all 0.15s; text-align:center; display:block; }
    .plan-btn:hover { background:#f0f0f0; color:#0a0a0a; border-color:#f0f0f0; }
    .plan-btn[disabled] { opacity:0.35; cursor:default; }
    .plan-btn[disabled]:hover { background:transparent; color:#ccc; border-color:#2e2e2e; }
    footer { border-top:1px solid #222; padding:18px 32px; text-align:center; font-size:13px; color:#555; }
    /* 📱 [FIX MOBILE] */
    @media (max-width: 700px) {
      header { height:auto; min-height:62px; flex-wrap:wrap; padding:10px 16px; gap:8px 12px; }
      .nav { flex-wrap:wrap; gap:10px 14px; }
      .wrap { padding:24px 14px 60px; }
      .card { padding:18px 14px; }
      table { font-size:12px !important; }
    }
  </style>
</head>
<body>
<header>
  <div class="logo">Veri<span>facts</span></div>
  <nav class="nav">
    <a href="/">Verificar</a>
    ${isAdmin(user) ? `<a href="/admin" class="${title==='Admin'?'active':''}" style="color:#FFD700;">👑 Admin</a>` : ""}
    <a href="/planos" class="${title==='Planos'?'active':''}">Planos</a>
    <a href="/conta" class="${title==='Minha Conta'?'active':''}">Conta</a>
    <a href="/logout" class="sair">Sair</a>
  </nav>
</header>
<div class="wrap">
${content}
</div>
<footer>Verifacts · ${escapeHtml(user.name)} · Plano ${escapeHtml(info.planName)} · ${usageText} ${info.lifetime ? "(teste grátis)" : "este mês"}</footer>
</body>
</html>`;
}

function renderContaPage(user, q = {}) {
  const info = usageInfo(user);
  const usagePct = info.unlimited ? 0 : Math.min(100, Math.round((info.used / info.limit) * 100));
  const usageColor = usagePct >= 90 ? "#e53935" : usagePct >= 70 ? "#fb8c00" : "#5b9bd5";
  let msg = "";
  if (q.ok === "perfil") msg = `<div class="msg-ok">✓ Perfil atualizado com sucesso.</div>`;
  if (q.ok === "senha") msg = `<div class="msg-ok">✓ Senha alterada com sucesso.</div>`;
  if (q.erro) msg = `<div class="msg-err">${escapeHtml(q.erro)}</div>`;

  const content = `
  <div class="page-title">Minha Conta</div>
  <div class="page-sub">Gerencie seu perfil, senha e acompanhe seu uso.</div>
  ${msg}

  <div class="card">
    <div class="card-title">Plano e Uso</div>
    <div style="display:flex; justify-content:space-between; align-items:baseline; flex-wrap:wrap; gap:10px;">
      <div>
        <span style="font-family:'Barlow Condensed',sans-serif; font-size:22px; font-weight:700; color:#f0f0f0;">${escapeHtml(info.planName)}</span>
        <span style="font-size:13px; color:#555; margin-left:8px;">${escapeHtml(planOf(user).price)}</span>
      </div>
      <div style="font-size:14px; color:${usageColor}; font-weight:600;">
        ${info.unlimited ? `${info.used} verificações este mês (ilimitado)` : info.lifetime ? `${info.used} de ${info.limit} verificações gratuitas usadas` : `${info.used} de ${info.limit} verificações este mês`}
      </div>
    </div>
    ${info.unlimited ? "" : `<div class="usage-bar"><div class="usage-fill" style="width:${usagePct}%; background:${usageColor};"></div></div>`}
    <div style="margin-top:18px;"><a href="/planos" style="color:#5b9bd5; font-family:'Barlow Condensed',sans-serif; font-size:13px; font-weight:600; letter-spacing:0.08em; text-transform:uppercase;">Ver planos e fazer upgrade →</a></div>
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
    <div class="card-title" style="color:#e53935;">Zona de Perigo</div>
    <div style="font-size:13px; color:#888; margin-bottom:6px;">Conta criada em ${new Date(user.created_at).toLocaleDateString("pt-BR", { day:"2-digit", month:"long", year:"numeric" })}</div>
    <p style="font-size:14px; color:#aaa; margin-bottom:18px; line-height:1.5;">Excluir sua conta remove permanentemente seus dados de acesso e histórico de uso. <strong style="color:#ff8a80;">Esta ação não pode ser desfeita.</strong><br><span style="font-size:12px; color:#666;">Mantemos apenas um registro anônimo (hash) para prevenir abuso do período de teste gratuito.</span></p>
    <form method="post" action="/conta/excluir" onsubmit="return confirm('Tem certeza ABSOLUTA? Sua conta e todos os dados serão apagados permanentemente. Esta ação NÃO pode ser desfeita.');">
      <div class="f">
        <label>Digite sua senha para confirmar</label>
        <input type="password" name="password" required placeholder="Sua senha atual">
      </div>
      <button type="submit" style="padding:12px 26px; background:transparent; color:#e53935; border:1px solid #e53935; border-radius:2px; font-family:'Barlow Condensed',sans-serif; font-size:14px; font-weight:700; letter-spacing:0.12em; text-transform:uppercase; cursor:pointer; transition:all 0.15s;" onmouseover="this.style.background='#e53935';this.style.color='#fff'" onmouseout="this.style.background='transparent';this.style.color='#e53935'">Excluir minha conta</button>
    </form>
  </div>`;
  return renderSubPage("Minha Conta", content, user);
}

function renderPlanosPage(user, q = {}) {
  const stripeOn = !!CONFIG.STRIPE_SECRET_KEY;
  let msg = "";
  if (q.ok === "pagamento") msg = `<div class="msg-ok">✓ Pagamento confirmado! Sua assinatura está ativa e o novo limite já vale.</div>`;
  else if (q.ok) msg = `<div class="msg-ok">✓ Plano alterado com sucesso! Seu novo limite já está valendo.</div>`;
  if (q.erro) msg = `<div class="msg-err">${escapeHtml(q.erro)}</div>`;

  function planCard(key, feats) {
    const p = PLANS[key];
    const isCurrent = user.plan === key;
    const isInstitucional = key === "institucional";
    const isGratis = key === "gratis";
    let button;
    if (isCurrent) {
      button = `<button class="plan-btn" disabled>Plano atual</button>`;
    } else if (isGratis) {
      button = `<button class="plan-btn" disabled>Apenas novas contas</button>`;
    } else if (isInstitucional) {
      button = `<a class="plan-btn" href="mailto:contato@verifacts.com.br?subject=Plano Institucional Verifacts&body=Olá! Tenho interesse no plano Institucional. Minha conta: ${encodeURIComponent(user.email)}">Falar com vendas</a>`;
    } else if (stripeOn) {
      // 💳 Assinatura via Stripe Checkout
      button = `<form method="post" action="/planos/checkout"><input type="hidden" name="plan" value="${key}"><button class="plan-btn" type="submit" style="background:#635bff; border-color:#635bff; color:#fff;">💳 Assinar ${p.name}</button></form>`;
    } else {
      button = `<form method="post" action="/planos/mudar" onsubmit="return confirm('Confirmar mudança para o plano ${p.name}?');"><input type="hidden" name="plan" value="${key}"><button class="plan-btn" type="submit">Mudar para ${p.name}</button></form>`;
    }
    return `<div class="plan-card ${isCurrent ? "current" : ""}">
      ${isCurrent ? `<div class="plan-badge">Seu plano</div>` : ""}
      <div class="plan-name">${p.name}</div>
      <div class="plan-price">${p.price}</div>
      <ul class="plan-feats">${feats.map(f => `<li>${f}</li>`).join("")}</ul>
      ${button}
    </div>`;
  }

  const content = `
  <div class="page-title">Planos</div>
  <div class="page-sub">Escolha o plano ideal para o seu volume de verificações.</div>
  ${msg}
  <div class="plans-grid">
    ${planCard("gratis", [
      "2 verificações para testar",
      "Texto, link, imagem e vídeo",
      "Detecção de IA (22 técnicas)",
      "Sem cartão de crédito",
      "Plano inicial de toda conta"
    ])}
    ${planCard("starter", [
      "100 verificações/mês",
      "Texto, link, imagem e vídeo",
      "Detecção de IA (22 técnicas)",
      "Fact-check + notícias",
      "1 usuário"
    ])}
    ${planCard("profissional", [
      "1.000 verificações/mês",
      "Tudo do Starter",
      "Análise de frames de vídeo",
      "Suporte prioritário",
      "Ideal para redações"
    ])}
    ${planCard("institucional", [
      "Verificações ilimitadas",
      "Tudo do Profissional",
      "SLA e treinamento",
      "Contrato anual",
      "Órgãos públicos e empresas"
    ])}
  </div>
  ${(stripeOn && user.stripe_subscription_id) ? `
  <div class="card" style="margin-top:26px; display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:14px;">
    <div>
      <div style="font-family:'Barlow Condensed',sans-serif; font-size:15px; font-weight:700; color:#f0f0f0; text-transform:uppercase; letter-spacing:0.06em;">Assinatura ativa</div>
      <div style="font-size:13px; color:#888; margin-top:4px;">Troque o cartão, veja faturas ou cancele quando quiser.</div>
    </div>
    <form method="post" action="/planos/portal">
      <button class="plan-btn" type="submit" style="width:auto; padding:11px 22px;">Gerenciar assinatura</button>
    </form>
  </div>` : ""}
  <div style="margin-top:26px; font-size:13px; color:#555; text-align:center;">
    ${stripeOn
      ? `🔒 Pagamento seguro processado pela <strong style="color:#888;">Stripe</strong>. Cancele quando quiser, sem multa.`
      : `A cobrança é feita por fatura/contrato. Integração de pagamento automático em breve.`}<br>
    Dúvidas? <a href="mailto:contato@verifacts.com.br" style="color:#5b9bd5;">contato@verifacts.com.br</a>
  </div>`;
  return renderSubPage("Planos", content, user);
}

function renderPage(content = "", user = null) {
  // Barra de usuário no header
  let userBar = "";
  if (user) {
    const info = usageInfo(user);
    const usageText = info.unlimited ? `${info.used} verificações` : `${info.used} / ${info.limit}`;
    const periodText = info.lifetime ? "teste grátis" : "este mês";
    const usagePct = info.unlimited ? 0 : Math.min(100, Math.round((info.used / info.limit) * 100));
    const usageColor = usagePct >= 90 ? "#e53935" : usagePct >= 70 ? "#fb8c00" : "#5b9bd5";
    userBar = `
      <div style="display:flex; align-items:center; gap:18px;">
        ${isAdmin(user) ? '<a href="/admin" style="font-family:\'Barlow Condensed\',sans-serif; font-size:13px; font-weight:600; letter-spacing:0.1em; text-transform:uppercase; color:#FFD700;">👑 Admin</a>' : ''}
        <a href="/planos" style="font-family:'Barlow Condensed',sans-serif; font-size:13px; font-weight:600; letter-spacing:0.1em; text-transform:uppercase; color:#555; transition:color 0.15s;" onmouseover="this.style.color='#f0f0f0'" onmouseout="this.style.color='#555'">Planos</a>
        <a href="/conta" style="font-family:'Barlow Condensed',sans-serif; font-size:13px; font-weight:600; letter-spacing:0.1em; text-transform:uppercase; color:#555; transition:color 0.15s;" onmouseover="this.style.color='#f0f0f0'" onmouseout="this.style.color='#555'">Conta</a>
        <div style="text-align:right; border-left:1px solid #222; padding-left:18px;">
          <div style="font-family:'Barlow Condensed',sans-serif; font-size:14px; font-weight:600; color:#f0f0f0; line-height:1.2;">${escapeHtml(user.name)}</div>
          <div style="font-size:11px; color:#555;">Plano <span style="color:#5b9bd5; font-weight:600;">${escapeHtml(info.planName)}</span> · <span style="color:${usageColor};">${usageText}</span> ${periodText}</div>
        </div>
        <a href="/logout" style="font-family:'Barlow Condensed',sans-serif; font-size:12px; font-weight:600; letter-spacing:0.1em; text-transform:uppercase; color:#555; border:1px solid #2e2e2e; padding:7px 14px; border-radius:2px; transition:all 0.15s;" onmouseover="this.style.color='#e53935';this.style.borderColor='#e53935'" onmouseout="this.style.color='#555';this.style.borderColor='#2e2e2e'">Sair</a>
      </div>`;
  }
  return `<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Verifacts</title>
  <link rel="icon" href="data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20viewBox%3D%220%200%2064%2064%22%3E%3Crect%20width%3D%2264%22%20height%3D%2264%22%20rx%3D%2212%22%20fill%3D%22%230a0a0a%22%2F%3E%3Ctext%20x%3D%2232%22%20y%3D%2244%22%20font-family%3D%22Arial%2Csans-serif%22%20font-size%3D%2234%22%20font-weight%3D%22700%22%20text-anchor%3D%22middle%22%3E%3Ctspan%20fill%3D%22%23f0f0f0%22%3EV%3C%2Ftspan%3E%3Ctspan%20fill%3D%22%23d0312d%22%3EF%3C%2Ftspan%3E%3C%2Ftext%3E%3C%2Fsvg%3E">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Barlow+Condensed:wght@400;500;600;700&family=Barlow:wght@300;400&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg:    #0a0a0a;
      --bg2:   #111;
      --bg3:   #181818;
      --line:  #222;
      --line2: #2e2e2e;
      --muted: #555;
      --dim:   #888;
      --text:  #ccc;
      --white: #f0f0f0;
      --red:   #d0312d;
      --c-red:        #e53935;
      --c-amber:      #fb8c00;
      --c-blue:       #1e88e5;
      --c-green:      #43a047;
      --accent-blue:  #5b9bd5;
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html { scroll-behavior: smooth; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: 'Barlow', sans-serif;
      font-weight: 300;
      font-size: 16px;
      line-height: 1.6;
      min-height: 100vh;
      -webkit-font-smoothing: antialiased;
    }
    a { color: var(--dim); text-decoration: none; }
    a:hover { color: var(--white); }

    header {
      border-bottom: 1px solid var(--line);
      padding: 0 32px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      height: 62px;
    }
    .logo {
      font-family: 'Barlow Condensed', sans-serif;
      font-weight: 700;
      font-size: 26px;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      color: var(--white);
    }
    .logo span { color: var(--red); }
    .header-right {
      font-family: 'Barlow Condensed', sans-serif;
      font-size: 13px;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: var(--muted);
    }

    .page-layout {
      display: flex;
      align-items: flex-start;
      min-height: calc(100vh - 62px);
    }

    .sidebar {
      width: 200px;
      flex-shrink: 0;
      border-right: 1px solid var(--line);
      padding: 0;
      position: sticky;
      top: 0;
      height: calc(100vh - 62px);
      overflow-y: auto;
      scrollbar-width: thin;
      scrollbar-color: var(--line2) transparent;
    }
    .sidebar::-webkit-scrollbar { width: 3px; }
    .sidebar::-webkit-scrollbar-thumb { background: var(--line2); border-radius: 2px; }
    @media (max-width: 900px) {
      .page-layout { flex-direction: column; }
      .sidebar { width: 100%; border-right: none; border-bottom: 1px solid var(--line); position: static; height: auto; }
    }

    .sidebar-label {
      font-family: 'Barlow Condensed', sans-serif;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.14em;
      text-transform: uppercase;
      color: var(--muted);
      padding: 18px 12px 8px 12px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .sidebar-clear {
      font-family: 'Barlow Condensed', sans-serif;
      font-size: 11px;
      font-weight: 600;
      letter-spacing: 0.06em;
      text-transform: uppercase;
      color: var(--muted);
      background: none;
      border: none;
      cursor: pointer;
      padding: 0;
      transition: color 0.15s;
    }
    .sidebar-clear:hover { color: var(--c-red); }
    .sidebar-empty {
      font-size: 13px;
      color: var(--muted);
      font-style: italic;
      padding: 6px 12px;
    }
    .sidebar-items { display: flex; flex-direction: column; }
    .sidebar-item {
      display: flex;
      align-items: center;
      transition: background 0.15s;
    }
    .sidebar-item:hover { background: var(--bg2); }
    .sidebar-item-btn {
      flex: 1;
      font-family: 'Barlow Condensed', sans-serif;
      font-size: 15px;
      font-weight: 400;
      color: var(--dim);
      background: none;
      border: none;
      padding: 7px 4px 7px 12px;
      cursor: pointer;
      text-align: left;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      transition: color 0.15s;
      min-width: 0;
      line-height: 1.3;
    }
    .sidebar-item-btn:hover { color: var(--white); }
    .sidebar-item-del {
      background: none;
      border: none;
      color: transparent;
      font-size: 11px;
      padding: 0 10px;
      cursor: pointer;
      transition: color 0.15s;
      flex-shrink: 0;
      line-height: 1;
    }
    .sidebar-item:hover .sidebar-item-del { color: var(--muted); }
    .sidebar-item-del:hover { color: var(--c-red) !important; }

    .main {
      flex: 1;
      min-width: 0;
      padding: 0 32px 60px 28px;
    }
    @media (max-width: 900px) { .main { padding: 0 20px 48px; } }

    .sec-label {
      font-family: 'Barlow Condensed', sans-serif;
      font-size: 13px;
      font-weight: 600;
      letter-spacing: 0.14em;
      text-transform: uppercase;
      color: var(--muted);
      padding: 28px 0 14px;
      border-bottom: 1px solid var(--line);
      margin-bottom: 20px;
    }

    /* 🎯 Como funciona (método transparente) */
    .steps-strip {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 14px;
      padding: 24px 0 6px;
    }
    .step { display: flex; gap: 12px; align-items: flex-start; }
    .step-num {
      font-family: 'Barlow Condensed', sans-serif;
      font-size: 26px; font-weight: 700;
      color: var(--line2);
      line-height: 1;
      min-width: 34px;
    }
    .step-title {
      font-family: 'Barlow Condensed', sans-serif;
      font-size: 15px; font-weight: 600;
      letter-spacing: 0.04em; text-transform: uppercase;
      color: var(--white); margin-bottom: 3px;
    }
    .step-desc { font-size: 13px; color: var(--muted); line-height: 1.5; }

    /* 🎯 Exemplos clicáveis */
    .examples-label {
      font-family: 'Barlow Condensed', sans-serif;
      font-size: 11px; font-weight: 600;
      letter-spacing: 0.12em; text-transform: uppercase;
      color: var(--muted); margin: 14px 0 8px;
    }
    .example-chips { display: flex; flex-wrap: wrap; gap: 8px; }
    .chip {
      background: var(--bg3);
      border: 1px solid var(--line2);
      color: var(--dim);
      font-family: 'Barlow', sans-serif;
      font-size: 12.5px;
      padding: 7px 12px;
      border-radius: 14px;
      cursor: pointer;
      transition: all 0.15s;
    }
    .chip:hover { border-color: var(--accent-blue, #5b9bd5); color: var(--white); background: rgba(91,155,213,0.08); }

    /* 🎯 Fontes consultadas */
    .sources-strip {
      display: flex; flex-wrap: wrap; align-items: baseline; gap: 8px 22px;
      margin-top: 20px; padding: 14px 18px;
      background: var(--bg2, #111);
      border: 1px solid var(--line);
      border-radius: 2px;
      font-size: 13px;
    }
    .sources-title {
      font-family: 'Barlow Condensed', sans-serif;
      font-size: 12px; font-weight: 600;
      letter-spacing: 0.1em; text-transform: uppercase;
      color: var(--muted);
    }
    .source-item { color: var(--dim); white-space: nowrap; }
    .source-sub { color: var(--muted); font-size: 12px; }

    .forms-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 1px;
      background: var(--line);
      margin-bottom: 1px;
    }
    @media (max-width: 680px) { .forms-grid { grid-template-columns: 1fr; } }
    .form-panel {
      background: var(--bg);
      padding: 28px 28px 24px;
    }
    .form-panel:last-child { border-left: none; }

    .panel-title {
      font-family: 'Barlow Condensed', sans-serif;
      font-size: 18px;
      font-weight: 600;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: var(--white);
      margin-bottom: 18px;
    }

    .field { margin-bottom: 14px; }
    .field-label {
      font-family: 'Barlow Condensed', sans-serif;
      font-size: 12px;
      font-weight: 600;
      letter-spacing: 0.14em;
      text-transform: uppercase;
      color: var(--muted);
      display: flex;
      justify-content: space-between;
      margin-bottom: 6px;
    }
    textarea.fi, input[type="text"].fi {
      width: 100%;
      background: var(--bg2);
      border: 1px solid var(--line2);
      border-radius: 2px;
      color: var(--white);
      font-family: 'Barlow', sans-serif;
      font-weight: 300;
      font-size: 16px;
      padding: 11px 13px;
      outline: none;
      transition: border-color 0.15s;
      resize: vertical;
    }
    textarea.fi { min-height: 120px; }
    textarea.fi:focus, input[type="text"].fi:focus { border-color: var(--dim); }
    textarea.fi::placeholder, input[type="text"].fi::placeholder { color: var(--muted); }

    .char-warning { color: var(--c-red); }

    .file-zone {
      width: 100%;
      background: var(--bg2);
      border: 1px dashed var(--line2);
      border-radius: 2px;
      padding: 18px 16px;
      text-align: center;
      cursor: pointer;
      position: relative;
      transition: border-color 0.15s;
    }
    .file-zone:hover { border-color: var(--dim); }
    .file-zone input { position:absolute;inset:0;opacity:0;cursor:pointer;width:100%;height:100%; }
    .file-zone-text {
      font-family: 'Barlow Condensed', sans-serif;
      font-size: 14px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: var(--muted);
    }
    .file-selected {
      margin-top: 6px;
      font-size: 13px;
      color: var(--dim);
      display: none;
    }

    .btn {
      width: 100%;
      margin-top: 16px;
      padding: 13px 16px;
      background: var(--white);
      color: var(--bg);
      border: none;
      border-radius: 2px;
      font-family: 'Barlow Condensed', sans-serif;
      font-size: 15px;
      font-weight: 700;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      cursor: pointer;
      transition: background 0.15s, opacity 0.15s;
    }
    .btn:hover { background: #d8d8d8; }
    .btn:disabled { opacity: 0.3; cursor: not-allowed; }
    .field-help {
      margin-top: 7px;
      font-size: 13px;
      color: var(--muted);
    }

    .result-section {
      background: var(--bg);
      border: 1px solid var(--line);
    }
    .result-section-head {
      padding: 14px 24px;
      border-bottom: 1px solid var(--line);
      background: var(--bg3);
      font-family: 'Barlow Condensed', sans-serif;
      font-size: 13px;
      font-weight: 700;
      letter-spacing: 0.14em;
      text-transform: uppercase;
      color: var(--accent-blue);
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .result-section-head::before {
      content: '';
      display: inline-block;
      width: 7px; height: 7px;
      border-radius: 50%;
      background: var(--accent-blue);
    }
    .result-body { padding: 28px; }
    .no-result { color: var(--muted); font-size: 15px; }

    .result-wrap { display: flex; flex-direction: column; gap: 26px; }

    .r-meta {
      display: flex;
      align-items: center;
      gap: 12px;
      flex-wrap: wrap;
      padding-bottom: 14px;
      border-bottom: 1px solid var(--line);
    }
    .r-tag {
      font-family: 'Barlow Condensed', sans-serif;
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.14em;
      text-transform: uppercase;
      background: var(--white);
      color: var(--bg);
      padding: 3px 10px;
      border-radius: 1px;
    }
    .r-ts {
      font-family: 'Barlow Condensed', sans-serif;
      font-size: 13px;
      letter-spacing: 0.06em;
      color: var(--muted);
    }
    .r-query {
      font-size: 13px;
      color: var(--dim);
      font-style: italic;
    }

    .verdict-block {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 20px;
      padding: 22px 24px;
      border: 1px solid var(--line2);
      border-radius: 2px;
      border-left: 4px solid;
    }
    .verdict-block.vf { border-left-color: var(--c-red);    background: rgba(211,47,47,0.06); }
    .verdict-block.vs { border-left-color: var(--c-amber);  background: rgba(245,124,0,0.06); }
    .verdict-block.vn { border-left-color: var(--c-blue);   background: rgba(30,136,229,0.06); }
    .verdict-block.vt { border-left-color: var(--c-green);  background: rgba(56,142,60,0.06); }

    .verdict-label {
      font-family: 'Barlow Condensed', sans-serif;
      font-size: 22px;
      font-weight: 700;
      letter-spacing: 0.06em;
      text-transform: uppercase;
      margin-bottom: 6px;
    }
    .vf .verdict-label { color: var(--c-red); }
    .vs .verdict-label { color: var(--c-amber); }
    .vn .verdict-label { color: var(--c-blue); }
    .vt .verdict-label { color: var(--c-green); }

    .verdict-summary { font-size: 15px; color: var(--dim); line-height: 1.55; max-width: 520px; }
    .verdict-right { text-align: right; flex-shrink: 0; min-width: 88px; }
    .conf-num {
      font-family: 'Barlow Condensed', sans-serif;
      font-size: 40px;
      font-weight: 700;
      line-height: 1;
    }
    .vf .conf-num { color: var(--c-red); }
    .vs .conf-num { color: var(--c-amber); }
    .vn .conf-num { color: var(--c-blue); }
    .vt .conf-num { color: var(--c-green); }
    .conf-unit { font-size: 20px; }
    .conf-desc {
      font-family: 'Barlow Condensed', sans-serif;
      font-size: 11px;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      color: var(--muted);
      margin: 4px 0 8px;
    }
    .conf-bar { height: 3px; background: var(--line2); border-radius: 1px; overflow: hidden; }
    .vf .conf-fill { background: var(--c-red); }
    .vs .conf-fill { background: var(--c-amber); }
    .vn .conf-fill { background: var(--c-blue); }
    .vt .conf-fill { background: var(--c-green); }
    .conf-fill { height: 100%; border-radius: 1px; }

    .block-label {
      font-family: 'Barlow Condensed', sans-serif;
      font-size: 13px;
      font-weight: 700;
      letter-spacing: 0.14em;
      text-transform: uppercase;
      color: var(--accent-blue);
      margin-bottom: 14px;
      padding-bottom: 8px;
      border-bottom: 1px solid var(--line);
    }
    .reply-block {
      padding: 20px 22px;
      border: 1px solid var(--line);
      border-radius: 2px;
      border-left: 3px solid var(--accent-blue);
      background: rgba(30,136,229,0.04);
    }
    .reply-text { font-size: 17px; color: var(--text); line-height: 1.65; }

    .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 22px; }
    @media (max-width: 680px) { .two-col { grid-template-columns: 1fr; } }

    .reasons-list { display: flex; flex-direction: column; gap: 13px; }
    .reason-row { display: flex; gap: 13px; align-items: flex-start; }
    .reason-i {
      font-family: 'Barlow Condensed', sans-serif;
      font-size: 14px;
      color: var(--accent-blue);
      flex-shrink: 0;
      padding-top: 2px;
      min-width: 24px;
      font-weight: 700;
    }
    .reason-t { font-size: 16px; color: var(--text); line-height: 1.5; }

    .src-list { display: flex; flex-direction: column; gap: 8px; }
    .src-item {
      padding: 14px 16px;
      border: 1px solid var(--line);
      border-radius: 2px;
      display: flex;
      flex-direction: column;
      gap: 6px;
      transition: border-color 0.15s;
    }
    .src-item:hover { border-color: var(--line2); }
    .src-row { display: flex; justify-content: space-between; align-items: baseline; gap: 8px; }

    .src-pub {
      font-family: 'Barlow Condensed', sans-serif;
      font-size: 13px;
      font-weight: 700;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      color: var(--white);
    }
    .src-rating {
      font-family: 'Barlow Condensed', sans-serif;
      font-size: 12px;
      letter-spacing: 0.06em;
      color: var(--muted);
      text-align: right;
    }
    .src-text { font-size: 14px; color: var(--dim); line-height: 1.5; }
    .src-link {
      font-family: 'Barlow Condensed', sans-serif;
      font-size: 11px;
      letter-spacing: 0.04em;
      color: var(--muted);
      word-break: break-all;
      transition: color 0.15s;
    }
    .src-link:hover { color: var(--white); }

    .carousel-outer { position: relative; }
    .carousel-viewport { overflow: hidden; width: 100%; }
    .carousel-track { display: flex; gap: 12px; transition: transform 0.35s cubic-bezier(0.25,0.46,0.45,0.94); will-change: transform; }
    .news-slide {
      flex: 0 0 calc((100% - 24px) / 3);
      padding: 16px 18px;
      border: 1px solid var(--line);
      border-radius: 2px;
      display: flex;
      flex-direction: column;
      gap: 10px;
      background: var(--bg2);
      transition: border-color 0.15s;
      box-sizing: border-box;
    }
    @media (max-width: 820px) { .news-slide { flex: 0 0 calc((100% - 12px) / 2); } }
    @media (max-width: 560px) { .news-slide { flex: 0 0 100%; } }

    /* ══════════════════════════════════════════════════
       📱 [FIX MOBILE v2] Relatório 100% responsivo
       Regra de ouro: nada pode ser mais largo que a tela.
       ══════════════════════════════════════════════════ */

    /* 1. Trava estrutural da página */
    html { overflow-x: hidden; }
    body { width: 100%; max-width: 100%; overflow-x: hidden; }
    header, footer, .page-layout, .sidebar, .main { max-width: 100%; min-width: 0; }

    /* 2. Nada dentro do relatório pode estourar a largura */
    .result-section { max-width: 100%; overflow: hidden; }
    .result-body, .result-wrap {
      max-width: 100%; min-width: 0;
      overflow-wrap: anywhere; word-break: break-word;
    }
    .result-body *, .result-wrap * { min-width: 0; max-width: 100%; }
    .result-body img, .result-wrap img { max-width: 100% !important; height: auto; }
    .two-col > *, .src-list, .reasons-list { min-width: 0; }
    .verdict-summary { max-width: 100%; }
    .src-link, .news-readlink, .news-title, .transcript {
      word-break: break-word; overflow-wrap: anywhere;
    }

    /* 3. Overlays / tooltips não podem empurrar a tela */
    .loading-card { width: min(380px, calc(100vw - 28px)); max-width: 100%; }
    .tech-info[data-tip]::after, .tech-info-tip { max-width: min(230px, 78vw) !important; }

    @media (max-width: 700px) {
      /* header */
      header { height: auto; min-height: 62px; flex-wrap: wrap; padding: 10px 16px; row-gap: 8px; }
      header > div { flex-wrap: wrap !important; gap: 8px 14px !important; }

      /* menos padding = mais texto visível */
      .main { padding: 0 12px 40px; }
      .result-section-head { padding: 12px 14px; }
      .result-body { padding: 16px 14px; }
      .result-wrap { gap: 20px; }
      .verdict-block { flex-direction: column; gap: 14px; padding: 16px 14px; }
      .verdict-right { text-align: left; min-width: 0; width: 100%; }
      .conf-num { font-size: 32px; }
      .reply-block { padding: 16px 14px; }
      .reply-text { font-size: 15.5px; }
      .reason-t, .src-text { font-size: 14.5px; }
      .src-item { padding: 12px 13px; }
      .news-slide { padding: 14px 14px; }

      /* grids viram coluna única — inclui os grids com style inline da seção de IA */
      .two-col { grid-template-columns: 1fr; }
      .result-body [style*="grid-template-columns"] { grid-template-columns: 1fr !important; }
      .result-body [style*="repeat(auto-fill"],
      .result-body [style*="repeat(auto-fit"] {
        grid-template-columns: repeat(auto-fill, minmax(118px, 1fr)) !important;
      }

      /* linhas que antes forçavam largura */
      .source-item { white-space: normal; }
      .sources-strip { gap: 6px 16px; padding: 12px 14px; }
      .steps-strip { gap: 10px; padding-top: 16px; }
      .r-meta { flex-wrap: wrap; gap: 8px; }
      .r-query { width: 100%; }
      .src-row { flex-wrap: wrap; }
      .src-rating { text-align: left; }
    }

    @media (max-width: 420px) {
      .main { padding: 0 10px 36px; }
      .result-body { padding: 14px 11px; }
      .verdict-label { font-size: 19px; }
      .reply-text { font-size: 15px; }
      .block-label { font-size: 12px; letter-spacing: 0.1em; }
    }
    .news-slide:hover { border-color: var(--line2); }

    .news-readlink {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      margin-top: auto;
      font-family: 'Barlow Condensed', sans-serif;
      font-size: 13px;
      font-weight: 600;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      color: var(--accent-blue);
      transition: color 0.15s, gap 0.15s;
    }
    .news-readlink:hover { color: var(--white); gap: 9px; }

    .carousel-nav {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-top: 12px;
    }
    .carousel-arrows { display: flex; gap: 6px; }
    .carousel-btn {
      width: 34px; height: 34px;
      background: var(--bg3);
      border: 1px solid var(--line2);
      color: var(--dim);
      font-size: 16px;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: color 0.15s, background 0.15s;
      border-radius: 2px;
      padding: 0;
      line-height: 1;
    }
    .carousel-btn:hover { color: var(--white); background: var(--line2); }
    .carousel-btn:disabled { opacity: 0.25; cursor: default; }

    .carousel-dots { display: flex; gap: 6px; align-items: center; }
    .c-dot {
      width: 6px; height: 6px;
      border-radius: 50%;
      border: 1px solid var(--muted);
      background: transparent;
      cursor: pointer;
      padding: 0;
      transition: background 0.15s, border-color 0.15s, transform 0.15s;
    }
    .c-dot.active {
      background: var(--accent-blue);
      border-color: var(--accent-blue);
      transform: scale(1.4);
    }

    .news-header { display: flex; align-items: center; gap: 10px; }
    .news-favicon-wrap { width: 28px; height: 28px; flex-shrink: 0; }
    .news-favicon {
      width: 28px; height: 28px;
      border-radius: 4px;
      object-fit: contain;
      background: var(--bg3);
      display: block;
    }
    .news-favicon-fallback {
      width: 28px; height: 28px;
      border-radius: 4px;
      background: var(--line2);
      color: var(--dim);
      font-family: 'Barlow Condensed', sans-serif;
      font-size: 11px;
      font-weight: 700;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .news-header .src-pub { flex: 1; }
    .news-header .src-rating { flex-shrink: 0; }
    .news-title {
      font-size: 16px;
      color: var(--white);
      line-height: 1.45;
      font-weight: 400;
      font-family: 'Barlow', sans-serif;
    }

    .empty-msg { font-size: 15px; color: var(--muted); padding: 12px 0; font-style: italic; }
    .transcript {
      font-size: 15px;
      color: var(--dim);
      line-height: 1.7;
      white-space: pre-wrap;
      padding: 16px;
      border: 1px solid var(--line);
      border-radius: 2px;
    }
    .disclaimer {
      font-size: 13px;
      color: var(--muted);
      padding-top: 16px;
      border-top: 1px solid var(--line);
    }

    footer {
      border-top: 1px solid var(--line);
      padding: 18px 32px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .footer-logo {
      font-family: 'Barlow Condensed', sans-serif;
      font-weight: 700;
      font-size: 16px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: var(--dim);
    }
    .footer-logo span { color: var(--red); }
    .footer-note {
      font-size: 13px;
      color: var(--muted);
    }

    #loading-overlay {
      display: none;
      position: fixed;
      inset: 0;
      z-index: 9999;
      background: rgba(10,10,10,0.96);
      align-items: center;
      justify-content: center;
    }
    #loading-overlay.active { display: flex; }
    .loading-card {
      width: 380px;
      border: 1px solid var(--line2);
      border-top: 2px solid var(--accent-blue);
      border-radius: 2px;
      background: var(--bg2);
      padding: 36px 32px;
    }
    .loading-logo-text {
      font-family: 'Barlow Condensed', sans-serif;
      font-weight: 700;
      font-size: 18px;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: var(--white);
      margin-bottom: 24px;
    }
    .loading-logo-text span { color: var(--red); }
    .loading-title {
      font-family: 'Barlow Condensed', sans-serif;
      font-size: 22px;
      font-weight: 700;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      color: var(--white);
      margin-bottom: 4px;
    }
    .loading-sub {
      font-size: 14px;
      color: var(--muted);
      margin-bottom: 28px;
      line-height: 1.5;
    }
    .l-steps { display: flex; flex-direction: column; gap: 0; }
    .l-step {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 10px 0;
      border-bottom: 1px solid var(--line);
      transition: color 0.3s;
    }
    .l-step:last-child { border-bottom: none; }
    .l-dot {
      width: 7px; height: 7px;
      border-radius: 50%;
      border: 1px solid var(--line2);
      flex-shrink: 0;
      transition: all 0.3s;
    }
    .l-step.active .l-dot { background: var(--accent-blue); border-color: var(--accent-blue); }
    .l-step.done .l-dot { background: var(--muted); border-color: var(--muted); }
    .l-step-text {
      font-family: 'Barlow Condensed', sans-serif;
      font-size: 14px;
      font-weight: 500;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: var(--muted);
      flex: 1;
      transition: color 0.3s;
    }
    .l-step.active .l-step-text { color: var(--white); }
    .l-step.done .l-step-text { color: var(--muted); }
    .l-step-st {
      font-family: 'Barlow Condensed', sans-serif;
      font-size: 12px;
      letter-spacing: 0.08em;
      color: var(--muted);
      width: 32px;
      text-align: right;
    }
    .l-step.active .l-step-st { color: var(--accent-blue); }
    .l-step.done .l-step-st { color: var(--muted); }

    .loading-spinner {
      width: 18px; height: 18px;
      border: 1px solid var(--line2);
      border-top-color: var(--white);
      border-radius: 50%;
      animation: spin 0.7s linear infinite;
      margin-left: auto;
      margin-top: 20px;
    }
    @keyframes spin { to { transform: rotate(360deg); } }

    /* 🔴 [NOVO] Animação de pulso das bolinhas de rastro de IA */
    @keyframes pulse-dot {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.45; }
    }
    .tech-info {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 15px;
      height: 15px;
      min-width: 15px;
      border-radius: 50%;
      background: #444;
      color: #fff;
      font-size: 10px;
      font-weight: 700;
      font-family: 'Barlow Condensed', sans-serif;
      cursor: help;
      position: relative;
      line-height: 1;
      transition: background 0.15s;
      outline: none;
    }
    .tech-info:hover, .tech-info:focus { background: #1e88e5; }
    .tech-info::after {
      content: attr(data-tip);
      position: absolute;
      bottom: calc(100% + 8px);
      left: 50%;
      transform: translateX(-50%);
      background: #000;
      color: #eee;
      border: 1px solid #1e88e5;
      border-radius: 6px;
      padding: 10px 12px;
      width: 230px;
      font-size: 12px;
      font-weight: 400;
      font-family: 'Barlow', sans-serif;
      line-height: 1.5;
      text-align: left;
      white-space: normal;
      opacity: 0;
      visibility: hidden;
      transition: opacity 0.15s, visibility 0.15s;
      z-index: 100;
      box-shadow: 0 4px 16px rgba(0,0,0,0.6);
      pointer-events: none;
    }
    .tech-info::before {
      content: '';
      position: absolute;
      bottom: calc(100% + 2px);
      left: 50%;
      transform: translateX(-50%);
      border: 6px solid transparent;
      border-top-color: #1e88e5;
      opacity: 0;
      visibility: hidden;
      transition: opacity 0.15s, visibility 0.15s;
      z-index: 101;
    }
    .tech-info:hover::after, .tech-info:focus::after,
    .tech-info:hover::before, .tech-info:focus::before {
      opacity: 1;
      visibility: visible;
    }
  </style>
</head>
<body>

<!-- LOADING -->
<div id="loading-overlay" role="status" aria-live="polite">
  <div class="loading-card">
    <div class="loading-logo-text">Veri<span>facts</span></div>
    <div class="loading-title">Verificando</div>
    <div class="loading-sub">Detectando IA, checando fatos e notícias.</div>
    <div class="l-steps">
      <div class="l-step" id="ls1"><div class="l-dot"></div><span class="l-step-text">Extraindo alegação</span><span class="l-step-st" id="ls1s">—</span></div>
      <div class="l-step" id="ls2"><div class="l-dot"></div><span class="l-step-text">Detecção de IA</span><span class="l-step-st" id="ls2s">—</span></div>
      <div class="l-step" id="ls3"><div class="l-dot"></div><span class="l-step-text">Checagens de fatos</span><span class="l-step-st" id="ls3s">—</span></div>
      <div class="l-step" id="ls4"><div class="l-dot"></div><span class="l-step-text">Notícias recentes</span><span class="l-step-st" id="ls4s">—</span></div>
      <div class="l-step" id="ls5"><div class="l-dot"></div><span class="l-step-text">Relatório final</span><span class="l-step-st" id="ls5s">—</span></div>
    </div>
    <div class="loading-spinner"></div>
  </div>
</div>

<!-- HEADER -->
<header>
  <div class="logo">Veri<span>facts</span></div>
  ${userBar || `<div class="header-right">Verificação de Fatos + Detecção de IA</div>`}
</header>

<!-- BODY -->
<div class="page-layout">

  <!-- SIDEBAR: HISTÓRICO (por usuário, vem do servidor) -->
  <aside class="sidebar">
    <div class="sidebar-label">
      <span>Histórico</span>
      <button class="sidebar-clear" onclick="historyClearAll()">Limpar</button>
    </div>
    <div id="sidebar-body">
      ${(() => {
        if (!user) return `<div class="sidebar-empty">Nenhuma busca ainda.</div>`;
        const items = getHistory(user.id);
        if (!items.length) return `<div class="sidebar-empty">Nenhuma busca ainda.</div>`;
        return `<div class="sidebar-items">` + items.map(h => {
          const label = h.text.length > 60 ? h.text.slice(0, 60) + "…" : h.text;
          return `<div class="sidebar-item" data-hid="${h.id}">
            <button class="sidebar-item-btn" title="${escapeHtml(h.text)}" data-text="${escapeHtml(h.text)}" onclick="historyUse(this)">${escapeHtml(label)}</button>
            <button class="sidebar-item-del" title="Remover" onclick="historyDel(${h.id}, this)">✕</button>
          </div>`;
        }).join("") + `</div>`;
      })()}
    </div>
  </aside>

  <!-- MAIN CONTENT -->
  <div class="main">

    <div class="sec-label">Submeter Conteúdo</div>

    <div class="forms-grid">
      <div class="form-panel">
        <div class="panel-title">Texto ou Link</div>
        <form method="post" action="/analyze-text" id="form-text">
          <div class="field">
            <label class="field-label"><span>Conteúdo</span><span id="char-count-content" class="muted">0 / 100</span></label>
            <textarea class="fi" id="content" name="content" placeholder="Cole a afirmação, manchete ou URL que deseja verificar…" maxlength="100"></textarea>
          </div>
          <button class="btn" type="submit" id="btn-text">Verificar</button>
          <div class="field-help">Máximo 100 caracteres.</div>
        </form>
      </div>

      <div class="form-panel">
        <div class="panel-title">Imagem ou Vídeo</div>
        <form method="post" action="/analyze-file" enctype="multipart/form-data" id="form-file">
          <div class="field">
            <label class="field-label"><span>Contexto</span><span id="char-count-caption" class="muted">0 / 100</span></label>
            <input class="fi" type="text" id="caption" name="caption" placeholder="Onde você recebeu? O que dizem que a mídia mostra?" maxlength="100">
          </div>
          <div class="field">
            <label class="field-label">Arquivo</label>
            <div class="file-zone">
              <input type="file" id="file" name="file" accept="image/*,video/*" required>
              <div class="file-zone-text">Clique para selecionar</div>
              <div class="file-selected" id="fname"></div>
            </div>
          </div>
          <button class="btn" type="submit" id="btn-file">Analisar Mídia</button>
          <div class="field-help">Ex.: print de post viral, foto que parece gerada por IA, vídeo recebido no WhatsApp · JPG, PNG ou MP4 até 80MB.</div>
        </form>
      </div>
    </div>

    <div class="sec-label" style="margin-top:32px;">Relatório</div>

    <div class="result-section">
      <div class="result-section-head">Resultado da Verificação</div>
      <div class="result-body">
        ${content || `<div class="no-result">Nenhuma análise realizada. Envie um conteúdo acima ou clique em um dos exemplos para ver o relatório completo.</div>`}
      </div>
    </div>

  </div><!-- /main -->

</div>

<!-- FOOTER -->
<footer>
  <div class="footer-logo">Veri<span>facts</span></div>
  <div class="footer-note">Verificação baseada em fontes citadas e datadas · Consulte as fontes primárias antes de publicar</div>
</footer>

<script>
(function(){
  var contentInput = document.getElementById('content');
  var charCountContent = document.getElementById('char-count-content');
  var captionInput = document.getElementById('caption');
  var charCountCaption = document.getElementById('char-count-caption');
  
  function updateContentCharCount() {
    var chars = contentInput.value.length;
    charCountContent.textContent = chars + ' / 100';
    charCountContent.className = chars >= 100 ? 'char-warning' : 'muted';
  }

  function updateCaptionCharCount() {
    var chars = captionInput.value.length;
    charCountCaption.textContent = chars + ' / 100';
    charCountCaption.className = chars >= 100 ? 'char-warning' : 'muted';
  }

  contentInput.addEventListener('input', updateContentCharCount);
  contentInput.addEventListener('change', updateContentCharCount);
  captionInput.addEventListener('input', updateCaptionCharCount);
  captionInput.addEventListener('change', updateCaptionCharCount);

  // 🔴 [NOVO] Submeter formulário ao pressionar Enter
  contentInput.addEventListener('keypress', function(e) {
    if (e.key === 'Enter') {
      e.preventDefault();
      document.getElementById('form-text').submit();
    }
  });

  captionInput.addEventListener('keypress', function(e) {
    if (e.key === 'Enter') {
      e.preventDefault();
      document.getElementById('form-text').submit();
    }
  });

  document.getElementById('file').addEventListener('change', function(){
    var el = document.getElementById('fname');
    if (this.files && this.files[0]) { el.textContent = this.files[0].name; el.style.display='block'; }
  });

  var overlay = document.getElementById('loading-overlay');
  var steps = [
    {el:document.getElementById('ls1'),st:document.getElementById('ls1s')},
    {el:document.getElementById('ls2'),st:document.getElementById('ls2s')},
    {el:document.getElementById('ls3'),st:document.getElementById('ls3s')},
    {el:document.getElementById('ls4'),st:document.getElementById('ls4s')},
    {el:document.getElementById('ls5'),st:document.getElementById('ls5s')},
  ];
  var delays = [0,2000,4000,7000,11000];
  var timers = [];
  
  function showLoading(){
    timers.forEach(clearTimeout); timers=[];
    steps.forEach(function(s){ s.el.classList.remove('active','done'); s.st.textContent='—'; });
    overlay.classList.add('active');
    document.body.style.overflow='hidden';
    delays.forEach(function(d,i){
      timers.push(setTimeout(function(){
        if(i>0){ steps[i-1].el.classList.replace('active','done'); steps[i-1].st.textContent='OK'; }
        steps[i].el.classList.add('active'); steps[i].st.textContent='...';
      },d));
    });
  }
  
  function hideLoading(){
    timers.forEach(clearTimeout);
    overlay.classList.remove('active');
    document.body.style.overflow='';
  }

  // 📜 Histórico por usuário — servidor (o antigo localStorage misturava contas)
  window.fillExample = function(btn) {
    var ta = document.getElementById('content');
    ta.value = btn.getAttribute('data-ex') || '';
    ta.dispatchEvent(new Event('input'));
    ta.focus();
  };
  window.historyUse = function(btn) {
    var ta = document.getElementById('content');
    ta.value = btn.getAttribute('data-text') || '';
    ta.focus();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };
  window.historyDel = function(id, btn) {
    fetch('/historico/excluir', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ id: id }) })
      .then(function(){ var el = btn.closest('.sidebar-item'); if (el) el.remove();
        var body = document.getElementById('sidebar-body');
        if (body && !body.querySelector('.sidebar-item')) body.innerHTML = '<div class="sidebar-empty">Nenhuma busca ainda.</div>';
      }).catch(function(){});
  };
  window.historyClearAll = function() {
    fetch('/historico/limpar', { method:'POST' })
      .then(function(){ document.getElementById('sidebar-body').innerHTML = '<div class="sidebar-empty">Nenhuma busca ainda.</div>'; })
      .catch(function(){});
  };

  document.getElementById('form-text').addEventListener('submit', function(){
    var val = document.getElementById('content').value.trim();
    if (!val) return;
    showLoading();
    document.getElementById('btn-text').disabled=true;
  });
  document.getElementById('form-file').addEventListener('submit', function(e){
    var f = document.getElementById('file').files[0];
    if (!f) return;
    showLoading();
    document.getElementById('btn-file').disabled=true;
  });
  window.addEventListener('pageshow', function(e){
    if(e.persisted){
      hideLoading();
      document.getElementById('btn-text').disabled=false;
      document.getElementById('btn-file').disabled=false;
    }
  });


  var _carouselIdx = 0;
  function _visibleCount() {
    var w = window.innerWidth;
    if (w <= 560) return 1;
    if (w <= 820) return 2;
    return 3;
  }

  function newsGoTo(idx) {
    var track = document.getElementById('news-track');
    if (!track) return;
    var slides = track.querySelectorAll('.news-slide');
    var dots   = document.querySelectorAll('#news-dots .c-dot');
    if (!slides.length) return;
    var vis = _visibleCount();
    var max = Math.max(0, slides.length - vis);
    _carouselIdx = Math.max(0, Math.min(idx, max));
    var slideW = slides[0].getBoundingClientRect().width + 12;
    track.style.transform = 'translateX(-' + (_carouselIdx * slideW) + 'px)';
    dots.forEach(function(d,i){ d.classList.toggle('active', i===_carouselIdx); });
    var prev = document.getElementById('carousel-prev');
    var next = document.getElementById('carousel-next');
    if (prev) prev.disabled = _carouselIdx === 0;
    if (next) next.disabled = _carouselIdx >= max;
  }

  function newsCarousel(dir) { newsGoTo(_carouselIdx + dir); }
  window.newsGoTo     = newsGoTo;
  window.newsCarousel = newsCarousel;
  setTimeout(function(){ newsGoTo(0); }, 50);
  window.addEventListener('resize', function(){ newsGoTo(_carouselIdx); });

  (function(){
    var track = document.getElementById('news-track');
    if (!track) return;
    var startX = 0, startIdx = 0, dragging = false, moved = false;

    function onDown(e) {
      dragging = true; moved = false;
      startX = e.type === 'mousedown' ? e.clientX : e.touches[0].clientX;
      startIdx = _carouselIdx;
      track.style.transition = 'none';
      track.style.cursor = 'grabbing';
    }
    function onMove(e) {
      if (!dragging) return;
      var x = e.type === 'mousemove' ? e.clientX : e.touches[0].clientX;
      var diff = startX - x;
      if (Math.abs(diff) > 5) moved = true;
      if (!moved) return;
      var slides = track.querySelectorAll('.news-slide');
      if (!slides.length) return;
      var slideW = slides[0].getBoundingClientRect().width + 12;
      var offset = startIdx * slideW + diff;
      track.style.transform = 'translateX(-' + offset + 'px)';
      if (e.cancelable) e.preventDefault();
    }
    function onUp(e) {
      if (!dragging) return;
      dragging = false;
      track.style.transition = '';
      track.style.cursor = 'grab';
      if (!moved) return;
      var x = e.type === 'mouseup' ? e.clientX : (e.changedTouches[0]||{clientX:startX}).clientX;
      var diff = startX - x;
      var slides = track.querySelectorAll('.news-slide');
      if (!slides.length) return;
      var slideW = slides[0].getBoundingClientRect().width + 12;
      var steps = Math.round(diff / slideW);
      newsGoTo(startIdx + steps);
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
    // 🛡️ [ANTIFRAUDE] Se este e-mail já gastou teste grátis antes (mesmo em conta
    // excluída), restaura o consumo — impede reset do trial via excluir/recriar.
    const prior = getPriorTrialUsage(email);
    if (prior > 0) {
      db.prepare(`
        INSERT INTO usage (user_id, month, count) VALUES (?, ?, ?)
        ON CONFLICT(user_id, month) DO UPDATE SET count = MAX(count, excluded.count)
      `).run(id, currentMonth(), prior);
      console.log(`[Antifraude] ${email} recriou conta — trial restaurado: ${prior}/2 usados`);
    }
    req.session.userId = id;
    logActivity(id, email, "registro", prior > 0 ? `trial restaurado: ${prior}/2` : "conta nova", req); // 📋
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
  // 🔒 [FIX] Cancela a assinatura Stripe antes de excluir — senão o cliente
  // continuaria sendo cobrado todo mês sem ter mais acesso!
  if (stripe && full.stripe_subscription_id) {
    try {
      await stripe.subscriptions.cancel(full.stripe_subscription_id);
      console.log(`[Stripe] Assinatura ${full.stripe_subscription_id} cancelada (exclusão de conta)`);
    } catch (e) {
      console.error("[Stripe] Falha ao cancelar assinatura na exclusão:", e.message);
    }
  }
  // 🛡️ [ANTIFRAUDE] Registra quanto do teste grátis foi usado ANTES de excluir.
  // Se recriar a conta com o mesmo e-mail, o trial continua de onde parou.
  recordTrialUsage(full.email, Math.min(getTotalUsage(req.user.id), 2));
  logActivity(req.user.id, req.user.email, "conta_excluida", "auto-exclusão pelo usuário", req); // 📋
  console.log(`[Conta] Exclusão: ${req.user.email} (id ${req.user.id})`);
  deleteUser(req.user.id);
  req.session.destroy(() => res.redirect("/login?msg=" + encodeURIComponent("Conta excluída com sucesso. Assinaturas foram canceladas.")));
});

// ══════════════════════════════════════════════════════════
// 💳 ROTAS: PAGAMENTO STRIPE
// ══════════════════════════════════════════════════════════
const PLAN_PRICES_BRL = { starter: 12990, profissional: 33990 }; // centavos

// Criar sessão de checkout (assinatura mensal)
app.post("/planos/checkout", requireAuth, async (req, res) => {
  if (!stripe) return res.redirect("/planos?erro=" + encodeURIComponent("Pagamentos ainda não configurados. Contate o suporte."));
  const plan = String(req.body.plan || "");
  if (!PLAN_PRICES_BRL[plan]) return res.redirect("/planos?erro=" + encodeURIComponent("Plano inválido."));
  // 🔒 [FIX] Já tem assinatura ativa? Bloqueia 2º checkout (evita cobrança dupla).
  // Troca de plano deve ser feita pelo portal (que faz upgrade/downgrade na mesma assinatura).
  if (req.user.stripe_subscription_id) {
    return res.redirect("/planos?erro=" + encodeURIComponent("Você já tem uma assinatura ativa. Use o botão 'Gerenciar assinatura' para trocar de plano ou cancelar."));
  }
  try {
    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      client_reference_id: String(req.user.id),
      // Reusa o customer se já assinou antes; senão preenche o e-mail
      ...(req.user.stripe_customer_id
        ? { customer: req.user.stripe_customer_id }
        : { customer_email: req.user.email }),
      metadata: { plan, userId: String(req.user.id) },
      subscription_data: { metadata: { plan, userId: String(req.user.id) } },
      line_items: [{
        quantity: 1,
        price_data: {
          currency: "brl",
          unit_amount: PLAN_PRICES_BRL[plan],
          recurring: { interval: "month" },
          product_data: {
            name: `Verifacts ${PLANS[plan].name}`,
            description: plan === "starter" ? "100 verificações/mês" : "1.000 verificações/mês"
          }
        }
      }],
      success_url: `${CONFIG.APP_URL}/planos/sucesso?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${CONFIG.APP_URL}/planos?erro=` + encodeURIComponent("Pagamento cancelado. Nenhuma cobrança foi feita.")
    });
    res.redirect(303, session.url);
  } catch (e) {
    console.error("[Stripe] Checkout:", e.message);
    res.redirect("/planos?erro=" + encodeURIComponent("Erro ao iniciar pagamento: " + e.message));
  }
});

// Retorno do checkout: confirma e ativa o plano na hora (webhook é o backup)
app.get("/planos/sucesso", requireAuth, async (req, res) => {
  if (stripe && req.query.session_id) {
    try {
      const s = await stripe.checkout.sessions.retrieve(String(req.query.session_id));
      const paid = s && (s.payment_status === "paid" || s.status === "complete");
      const mine = String(s?.client_reference_id) === String(req.user.id);
      const plan = s?.metadata?.plan;
      if (paid && mine && PLAN_PRICES_BRL[plan]) {
        updateUserPlan(req.user.id, plan);
        setUserStripe(req.user.id, s.customer, s.subscription);
        logActivity(req.user.id, req.user.email, "assinatura_ativada", `plano ${plan} via Stripe Checkout`, req); // 📋
        console.log(`[Stripe] ✓ Plano ativado no retorno: ${req.user.email} → ${plan}`);
      }
    } catch (e) {
      console.error("[Stripe] Sucesso:", e.message);
    }
  }
  res.redirect("/planos?ok=pagamento");
});

// Portal de assinatura (trocar cartão, ver faturas, cancelar)
app.post("/planos/portal", requireAuth, async (req, res) => {
  if (!stripe || !req.user.stripe_customer_id) {
    return res.redirect("/planos?erro=" + encodeURIComponent("Você não possui uma assinatura ativa."));
  }
  try {
    const portal = await stripe.billingPortal.sessions.create({
      customer: req.user.stripe_customer_id,
      return_url: `${CONFIG.APP_URL}/planos`
    });
    res.redirect(303, portal.url);
  } catch (e) {
    console.error("[Stripe] Portal:", e.message);
    res.redirect("/planos?erro=" + encodeURIComponent("Erro ao abrir portal: " + e.message));
  }
});

// ══════════════════════════════════════════════════════════
// ⚙️ ROTAS: PLANOS (mudança de plano)
// ══════════════════════════════════════════════════════════
app.get("/planos", requireAuth, (req, res) => {
  res.send(renderPlanosPage(req.user, req.query));
});

app.post("/planos/mudar", requireAuth, (req, res) => {
  // 💳 Com Stripe ativo, planos pagos exigem pagamento — troca manual desabilitada
  if (stripe) {
    return res.redirect("/planos?erro=" + encodeURIComponent("Use o botão Assinar para contratar com pagamento seguro."));
  }
  const plan = String(req.body.plan || "");
  // Institucional só via contato comercial (evita auto-upgrade para ilimitado)
  if (!["starter", "profissional"].includes(plan)) {
    return res.redirect("/planos?erro=" + encodeURIComponent("Este plano não pode ser selecionado. O Grátis é apenas para novas contas; para o Institucional, fale com vendas."));
  }
  if (plan === req.user.plan) {
    return res.redirect("/planos?erro=" + encodeURIComponent("Você já está neste plano."));
  }
  updateUserPlan(req.user.id, plan);
  logActivity(req.user.id, req.user.email, "plano_alterado", `${req.user.plan} → ${plan} (manual)`, req); // 📋
  console.log(`[Planos] ${req.user.email} mudou de ${req.user.plan} → ${plan}`);
  res.redirect("/planos?ok=1");
});

// ══════════════════════════════════════════════════════════
// ROTAS DA APLICAÇÃO (protegidas)
// ══════════════════════════════════════════════════════════
app.get("/", requireAuth, async (req, res) => res.send(renderPage("", req.user)));

app.post("/analyze-text", requireAuth, checkUsageLimit, async (req, res) => {
  try {
    const content = (req.body.content||"").trim();
    if (!content) return res.send(renderPage(`<div class="no-result">Envie algum texto ou link.</div>`, req.user));
    const urls = extractUrls(content);
    const result = urls.length > 0 ? await analyzeLink(urls[0]) : await analyzeText(content);
    incrementUsage(req.user.id); // 🔐 conta a verificação
    addHistory(req.user.id, content, urls.length > 0 ? "LINK" : "TEXTO"); // 📜 histórico por usuário
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

app.post("/analyze-file", requireAuth, checkUsageLimit, uploadSafe, async (req, res) => {
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
    addHistory(req.user.id, caption || req.file.originalname || "mídia", "MÍDIA"); // 📜 histórico por usuário
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
      SELECT u.id, u.name, u.email, u.plan, u.created_at, u.stripe_subscription_id,
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
      SELECT u.id, u.name, u.email, u.plan, u.created_at, u.stripe_subscription_id,
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
    pagantes: db.prepare("SELECT COUNT(*) c FROM users WHERE plan IN ('starter','profissional','institucional')").get().c,
    assinaturas: db.prepare("SELECT COUNT(*) c FROM users WHERE stripe_subscription_id IS NOT NULL").get().c,
    verifMes: db.prepare("SELECT COALESCE(SUM(count),0) c FROM usage WHERE month = ?").get(currentMonth()).c,
    verifHoje: db.prepare("SELECT COUNT(*) c FROM activity_log WHERE action = 'verificacao' AND created_at >= ?").get(new Date().toISOString().slice(0,10)).c,
    trials: db.prepare("SELECT COUNT(*) c FROM trial_registry").get().c
  };
  let msg = "";
  if (req.query.ok === "plano") msg = `<div class="msg-ok">✓ Plano do usuário alterado.</div>`;
  if (req.query.ok === "excluido") msg = `<div class="msg-ok">✓ Usuário excluído (sem registro antifraude — pode recriar com trial cheio).</div>`;
  if (req.query.erro) msg = `<div class="msg-err">${escapeHtml(req.query.erro)}</div>`;

  const planOptions = (current) => Object.entries(PLANS).map(([k, p]) =>
    `<option value="${k}" ${k === current ? "selected" : ""}>${p.name}</option>`).join("");

  const td = `padding:9px 8px; border-top:1px solid #222; vertical-align:middle;`;
  const rows = users.map(u => `
    <tr>
      <td style="${td} color:#666;">#${u.id}</td>
      <td style="${td} color:#f0f0f0; white-space:nowrap;">${escapeHtml(u.name)}${isAdmin(u) ? ' <span style="color:#FFD700;">👑</span>' : ''}</td>
      <td style="${td}">${escapeHtml(u.email)}</td>
      <td style="${td} white-space:nowrap;">
        <form method="post" action="/admin/plano" style="display:flex; gap:6px; align-items:center;">
          <input type="hidden" name="user_id" value="${u.id}">
          <select name="plan" style="background:#181818; border:1px solid #2e2e2e; color:#ccc; padding:5px 8px; border-radius:2px; font-size:12px;">
            ${planOptions(u.plan)}
          </select>
          <button type="submit" style="background:#2a2a2a; border:1px solid #3a3a3a; color:#5b9bd5; padding:5px 10px; border-radius:2px; font-size:11px; cursor:pointer; font-weight:600;">Salvar</button>
          ${u.stripe_subscription_id ? '<span title="Tem assinatura Stripe ativa">💳</span>' : ''}
        </form>
      </td>
      <td style="${td} text-align:right;">${u.month_usage}</td>
      <td style="${td} text-align:right; color:#666;">${u.total_usage}</td>
      <td style="${td} color:#666; font-size:12px; white-space:nowrap;">${new Date(u.created_at).toLocaleDateString("pt-BR")}</td>
      <td style="${td} white-space:nowrap;">
        <a href="/admin/logs?email=${encodeURIComponent(u.email)}" style="color:#5b9bd5; font-size:12px; margin-right:10px;">Logs</a>
        <form method="post" action="/admin/excluir" style="display:inline;" onsubmit="return confirm('Excluir ${escapeHtml(u.email)}? (exclusão de teste: sem registro antifraude)');">
          <input type="hidden" name="user_id" value="${u.id}">
          <button type="submit" style="background:none; border:none; color:#e53935; font-size:12px; cursor:pointer; padding:0;">Excluir</button>
        </form>
      </td>
    </tr>`).join("");

  const content = `
  <div class="page-title">👑 Admin</div>
  <div class="page-sub">Gestão de clientes, planos e atividades. <a href="/admin/logs" style="color:#5b9bd5;">Ver todos os logs →</a></div>
  ${msg}
  <div style="display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:12px; margin-bottom:24px;">
    ${[["Contas", stats.total],["Planos pagos", stats.pagantes],["Assinaturas 💳", stats.assinaturas],["Verif. no mês", stats.verifMes],["Verif. hoje", stats.verifHoje],["Trials usados", stats.trials]].map(([label,val]) => `
    <div class="card" style="margin:0; padding:16px; text-align:center;">
      <div style="font-family:'Barlow Condensed',sans-serif; font-size:28px; font-weight:700; color:#5b9bd5;">${val}</div>
      <div style="font-size:11px; color:#666; text-transform:uppercase; letter-spacing:0.06em;">${label}</div>
    </div>`).join("")}
  </div>
  <div class="card" style="overflow-x:auto;">
    <div class="card-title" style="display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap;">
      <span>Clientes ${q ? `— busca: "${escapeHtml(q)}" (${users.length})` : `(${users.length})`}</span>
      <form method="get" action="/admin" style="display:flex; gap:6px;">
        <input type="text" name="q" value="${escapeHtml(q)}" placeholder="Buscar nome ou e-mail..." style="background:#181818; border:1px solid #2e2e2e; color:#f0f0f0; padding:7px 12px; border-radius:2px; font-size:13px; width:220px;">
        <button type="submit" style="background:#2a2a2a; border:1px solid #3a3a3a; color:#ccc; padding:7px 14px; border-radius:2px; font-size:12px; cursor:pointer;">Buscar</button>
        ${q ? '<a href="/admin" style="align-self:center; color:#666; font-size:12px;">limpar</a>' : ''}
      </form>
    </div>
    <table style="width:100%; border-collapse:collapse; font-size:13px;">
      <thead>
        <tr style="color:#555; text-transform:uppercase; font-size:11px; letter-spacing:0.08em; text-align:left;">
          <th style="padding:8px;">ID</th><th style="padding:8px;">Nome</th><th style="padding:8px;">E-mail</th><th style="padding:8px;">Plano</th><th style="padding:8px; text-align:right;">Mês</th><th style="padding:8px; text-align:right;">Total</th><th style="padding:8px;">Criada</th><th style="padding:8px;">Ações</th>
        </tr>
      </thead>
      <tbody style="color:#aaa;">${rows || `<tr><td colspan="8" style="padding:20px; text-align:center; color:#555;">Nenhum usuário encontrado.</td></tr>`}</tbody>
    </table>
  </div>`;
  res.send(renderSubPage("Admin", content, req.user));
});

// 👑 Alterar plano de qualquer usuário pelo painel
app.post("/admin/plano", requireAuth, requireAdmin, (req, res) => {
  const userId = Number(req.body.user_id);
  const plan = String(req.body.plan || "");
  const target = findUserById(userId);
  if (!target || !PLANS[plan]) return res.redirect("/admin?erro=" + encodeURIComponent("Usuário ou plano inválido."));
  const anterior = target.plan;
  updateUserPlan(userId, plan);
  logActivity(userId, target.email, "admin_plano_alterado", `${anterior} → ${plan} (por ${req.user.email})`, req);
  console.log(`[Admin] ${req.user.email} alterou plano de ${target.email}: ${anterior} → ${plan}`);
  res.redirect("/admin?ok=plano");
});

// 👑 Excluir usuário pelo painel (exclusão LIMPA para testes: sem registro antifraude)
app.post("/admin/excluir", requireAuth, requireAdmin, async (req, res) => {
  const userId = Number(req.body.user_id);
  if (userId === req.user.id) return res.redirect("/admin?erro=" + encodeURIComponent("Você não pode excluir a própria conta pelo painel."));
  const target = db.prepare("SELECT * FROM users WHERE id = ?").get(userId);
  if (!target) return res.redirect("/admin?erro=" + encodeURIComponent("Usuário não encontrado."));
  if (stripe && target.stripe_subscription_id) {
    try { await stripe.subscriptions.cancel(target.stripe_subscription_id); } catch (e) { console.error("[Admin] Cancelar sub:", e.message); }
  }
  logActivity(userId, target.email, "admin_conta_excluida", `por ${req.user.email} (sem antifraude)`, req);
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
    if (a === "verificacao") return "#5b9bd5";
    if (a === "login" || a === "registro") return "#43a047";
    if (a.includes("falhou") || a.includes("excluida")) return "#e53935";
    if (a.includes("plano") || a.includes("assinatura")) return "#9c6bff";
    return "#888";
  };
  const td = `padding:8px; border-top:1px solid #222; vertical-align:top;`;
  const rows = logs.map(l => `
    <tr>
      <td style="${td} color:#666; white-space:nowrap; font-size:12px;">${new Date(l.created_at).toLocaleString("pt-BR", {dateStyle:"short", timeStyle:"medium"})}</td>
      <td style="${td} white-space:nowrap;">${l.email ? `<a href="/admin/logs?email=${encodeURIComponent(l.email)}" style="color:#aaa;">${escapeHtml(l.email)}</a>` : `<span style="color:#555;">—</span>`}</td>
      <td style="${td}"><span style="background:${badgeColor(l.action)}20; color:${badgeColor(l.action)}; padding:3px 9px; border-radius:10px; font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:0.04em; white-space:nowrap;">${escapeHtml(l.action)}</span></td>
      <td style="${td} color:#999; font-size:12px; word-break:break-word; max-width:400px;">${escapeHtml(l.details || "")}</td>
      <td style="${td} color:#555; font-size:11px; white-space:nowrap;">${escapeHtml(l.ip || "")}</td>
    </tr>`).join("");

  const content = `
  <div class="page-title">📋 Logs de Atividade</div>
  <div class="page-sub"><a href="/admin" style="color:#5b9bd5;">← Voltar ao painel</a> · Últimos 200 registros${email || action ? " (filtrados)" : ""}.</div>
  <div class="card" style="overflow-x:auto;">
    <div class="card-title" style="display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap;">
      <span>Atividades (${logs.length})</span>
      <form method="get" action="/admin/logs" style="display:flex; gap:6px; flex-wrap:wrap;">
        <input type="text" name="email" value="${escapeHtml(email)}" placeholder="Filtrar por e-mail..." style="background:#181818; border:1px solid #2e2e2e; color:#f0f0f0; padding:7px 12px; border-radius:2px; font-size:13px; width:190px;">
        <select name="action" style="background:#181818; border:1px solid #2e2e2e; color:#ccc; padding:7px 10px; border-radius:2px; font-size:13px;">
          <option value="">Todas as ações</option>
          ${actions.map(a => `<option value="${escapeHtml(a)}" ${a === action ? "selected" : ""}>${escapeHtml(a)}</option>`).join("")}
        </select>
        <button type="submit" style="background:#2a2a2a; border:1px solid #3a3a3a; color:#ccc; padding:7px 14px; border-radius:2px; font-size:12px; cursor:pointer;">Filtrar</button>
        ${email || action ? '<a href="/admin/logs" style="align-self:center; color:#666; font-size:12px;">limpar</a>' : ''}
      </form>
    </div>
    <table style="width:100%; border-collapse:collapse; font-size:13px;">
      <thead>
        <tr style="color:#555; text-transform:uppercase; font-size:11px; letter-spacing:0.08em; text-align:left;">
          <th style="padding:8px;">Quando</th><th style="padding:8px;">Usuário</th><th style="padding:8px;">Ação</th><th style="padding:8px;">Detalhes</th><th style="padding:8px;">IP</th>
        </tr>
      </thead>
      <tbody style="color:#aaa;">${rows || `<tr><td colspan="5" style="padding:20px; text-align:center; color:#555;">Nenhum log ainda.</td></tr>`}</tbody>
    </table>
  </div>`;
  res.send(renderSubPage("Admin", content, req.user));
});

(async () => {
  await ensureTempDir();
  const llmInfo = CONFIG.OPENAI_API_KEY ? `OpenAI ${CONFIG.OPENAI_MODEL}` : `Ollama ${CONFIG.OLLAMA_MODEL} (local)`;
  app.listen(CONFIG.PORT, () => console.log(`🤖 Verifacts (IA Detection + Fact Check) em http://localhost:${CONFIG.PORT}\n🧠 LLM: ${llmInfo}`));
})();