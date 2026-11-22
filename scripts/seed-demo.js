// Loads the synthetic reports in examples/synthetic-reports.json into the local
// database for a demo account, so the interface can be explored without API
// keys or personal data. All sources and links in the examples are fictional.
//
// Usage: npm run seed:demo   (then: npm start, and sign in with the demo account)
"use strict";

require("dotenv").config();
const fs = require("node:fs");
const path = require("node:path");
const { spawn } = require("node:child_process");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");

const ROOT = path.join(__dirname, "..");
const DB_PATH = path.resolve(ROOT, process.env.DB_PATH || "./verifacts.db");
const DEMO = { name: "Conta de demonstração", email: "demo@example.org", password: "ecoa-demo-2026" };
const EXAMPLES = JSON.parse(fs.readFileSync(path.join(ROOT, "examples", "synthetic-reports.json"), "utf8"));

function schemaReady() {
  if (!fs.existsSync(DB_PATH)) return false;
  try {
    const db = new Database(DB_PATH, { readonly: true, fileMustExist: true });
    const users = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'users'").get();
    const columns = db.prepare("PRAGMA table_info(history)").all().map((c) => c.name);
    db.close();
    return Boolean(users) && columns.includes("result_json");
  } catch (_) {
    return false;
  }
}

// Starts the app once so that it creates its own tables, then stops it.
async function ensureSchema() {
  if (schemaReady()) return;
  const app = spawn(process.execPath, [path.join(ROOT, "app.js")], {
    cwd: ROOT,
    env: { ...process.env, PORT: "0", DB_PATH },
    stdio: "ignore"
  });
  const deadline = Date.now() + 30000;
  try {
    while (!schemaReady()) {
      if (Date.now() > deadline) throw new Error("Could not create the database. Run `npm start` once and try again.");
      await new Promise((r) => setTimeout(r, 200));
    }
  } finally {
    app.kill();
  }
}

async function main() {
  await ensureSchema();
  const db = new Database(DB_PATH);
  db.pragma("busy_timeout = 5000");

  let user = db.prepare("SELECT id FROM users WHERE email = ?").get(DEMO.email);
  if (!user) {
    const info = db
      .prepare("INSERT INTO users (name, email, password_hash, plan, created_at) VALUES (?, ?, ?, ?, ?)")
      .run(DEMO.name, DEMO.email, bcrypt.hashSync(DEMO.password, 10), "ilimitado", new Date().toISOString());
    user = { id: info.lastInsertRowid };
  }

  const insert = db.prepare(
    "INSERT INTO history (user_id, text, type, created_at, verdict, summary, result_json) VALUES (?, ?, ?, ?, ?, ?, ?)"
  );
  const load = db.transaction((reports) => {
    db.prepare("DELETE FROM history WHERE user_id = ?").run(user.id);
    const now = Date.now();
    reports.forEach((r, i) => {
      const when = new Date(now - (reports.length - i) * 3600 * 1000).toISOString();
      insert.run(user.id, r.question, r.type || "TEXTO", when, r.result.verdict, r.result.summary, JSON.stringify(r.result));
    });
  });
  load(EXAMPLES.reports);
  db.close();

  console.log(`Loaded ${EXAMPLES.reports.length} synthetic reports into ${DB_PATH}.`);
  console.log(`Start the server (npm start) and sign in with ${DEMO.email} / ${DEMO.password}.`);
}

main().catch((e) => {
  console.error(e.message);
  process.exit(1);
});
