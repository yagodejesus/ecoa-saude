// Smoke test for Ecoa Saúde.
// Starts the server against simulated services (language model, Google Fact
// Check Tools API and Google News RSS), creates an account, runs one text check
// and one image screening, and reopens the stored report. No API keys or
// network access are needed. Run with: npm test
"use strict";

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const net = require("node:net");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const sharp = require("sharp");

const ROOT = path.join(__dirname, "..");
const VERDICTS = ["provavelmente_falso", "suspeito", "nao_verificado", "provavelmente_verdadeiro"];

let mock, server, base, token, tmp, logs = "";

// ---------------------------------------------------------------- simulated services
function startMockServices() {
  const srv = http.createServer((req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");

    // Ollama chat endpoint: one answer that serves both model calls
    // (claim extraction and verdict), each of which reads only its own fields.
    if (req.method === "POST" && url.pathname === "/api/chat") {
      req.resume();
      req.on("end", () => {
        const answer = {
          claim: "Chá de alho com limão cura a gripe em um dia.",
          query: "chá de alho gripe",
          is_dynamic: false,
          verdict: "provavelmente_falso",
          confidence: 0.8,
          summary: "Resposta simulada para o teste.",
          reasons: ["A Agência Exemplo classificou a alegação como falsa em 02/11/2026 (fonte simulada)."],
          reply: "Conclusão simulada para o teste."
        };
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify({ message: { role: "assistant", content: JSON.stringify(answer) }, done: true }));
      });
      return;
    }

    // Google Fact Check Tools API (claims:search)
    if (url.pathname === "/factcheck") {
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({
        claims: [{
          text: "Chá de alho com limão cura a gripe",
          claimant: "Mensagem em rede social",
          claimDate: "2026-11-01T00:00:00Z",
          claimReview: [{
            publisher: { name: "Agência Exemplo" },
            title: "É falso que chá de alho cure a gripe",
            textualRating: "Falso",
            url: "https://example.org/checagem/cha-de-alho",
            reviewDate: "2026-11-02T00:00:00Z"
          }]
        }]
      }));
      return;
    }

    // Google News RSS search
    if (url.pathname === "/rss") {
      res.setHeader("Content-Type", "application/rss+xml; charset=utf-8");
      res.end(`<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
<item>
  <title>Médicos explicam o que é mito sobre a gripe</title>
  <link>https://example.org/noticias/gripe-mitos</link>
  <pubDate>Mon, 02 Nov 2026 12:00:00 GMT</pubDate>
  <source url="https://example.org">Jornal Exemplo</source>
</item>
</channel></rss>`);
      return;
    }

    res.statusCode = 404;
    res.end();
  });
  return new Promise((resolve) => srv.listen(0, "127.0.0.1", () => resolve(srv)));
}

function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.on("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });
}

async function waitForHealth(url, ms = 30000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    try {
      const r = await fetch(url + "/health");
      if (r.ok) return;
    } catch (_) { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error("The server did not start.\n" + logs);
}

async function api(method, route, body, isForm = false) {
  const headers = token ? { Authorization: `Bearer ${token}` } : {};
  if (body && !isForm) headers["Content-Type"] = "application/json";
  const r = await fetch(base + route, {
    method,
    headers,
    body: body ? (isForm ? body : JSON.stringify(body)) : undefined
  });
  const text = await r.text();
  let json = null;
  try { json = JSON.parse(text); } catch (_) { /* not JSON */ }
  return { status: r.status, json, text };
}

// ---------------------------------------------------------------- setup
before(async () => {
  mock = await startMockServices();
  const mockUrl = `http://127.0.0.1:${mock.address().port}`;
  const port = await freePort();
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "ecoa-saude-test-"));
  base = `http://127.0.0.1:${port}`;

  // Variables set here take precedence over a local .env file.
  const env = {
    ...process.env,
    PORT: String(port),
    NODE_ENV: "test",
    APP_URL: base,
    SESSION_SECRET: "test-secret",
    DB_PATH: path.join(tmp, "test.db"),
    TEMP_DIR: path.join(tmp, "tmp"),
    OPENAI_API_KEY: "",
    OLLAMA_HOST: mockUrl,
    OLLAMA_MODEL: "simulated",
    GOOGLE_FACTCHECK_API_KEY: "test-key",
    FACTCHECK_API_URL: `${mockUrl}/factcheck`,
    NEWS_RSS_URL: `${mockUrl}/rss`,
    ADMIN_EMAILS: "",
    SMTP_HOST: "",
    WHISPER_COMMAND: ""
  };
  server = spawn(process.execPath, ["app.js"], { cwd: ROOT, env, stdio: ["ignore", "pipe", "pipe"] });
  server.stdout.on("data", (d) => { logs += d; });
  server.stderr.on("data", (d) => { logs += d; });
  await waitForHealth(base);
});

after(() => {
  if (server) server.kill();
  if (mock) mock.close();
  if (tmp) fs.rmSync(tmp, { recursive: true, force: true });
});

// ---------------------------------------------------------------- tests
test("creates an account and receives an API token", async () => {
  const r = await api("POST", "/api/auth/register", { email: "teste@example.org", password: "senha-de-teste" });
  assert.equal(r.status, 200, r.text);
  assert.ok(r.json.token, "token missing");
  token = r.json.token;
});

test("text check runs the three-stage pipeline", async () => {
  const r = await api("POST", "/api/verify", { content: "Chá de alho com limão cura a gripe em um dia?" });
  assert.equal(r.status, 200, r.text);
  assert.ok(VERDICTS.includes(r.json.verdict), `unexpected verdict: ${r.json.verdict}`);
  assert.equal(typeof r.json.confidence, "number");
  assert.ok(r.json.reasons.length >= 1, "no reasons");
  assert.ok(r.json.factChecks.length >= 1, "fact-check retrieval returned nothing");
  assert.ok(r.json.news.length >= 1, "news retrieval returned nothing");
});

test("the report is stored and can be reopened", async () => {
  const list = await api("GET", "/api/history");
  assert.equal(list.status, 200, list.text);
  assert.ok(list.json.length >= 1, "history is empty");
  const item = list.json[0];
  assert.ok(VERDICTS.includes(item.verdict));
  const full = await api("GET", `/api/history/${item.id}/result`);
  assert.equal(full.status, 200, full.text);
});

test("image screening returns a score and the 22 indicators", async () => {
  const width = 160, height = 120;
  const raw = Buffer.alloc(width * height * 3);
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const i = (y * width + x) * 3;
      raw[i] = (x * 255) / width;
      raw[i + 1] = (y * 255) / height;
      raw[i + 2] = ((x + y) * 7) % 256;
    }
  }
  const png = await sharp(raw, { raw: { width, height, channels: 3 } }).png().toBuffer();
  const form = new FormData();
  form.append("file", new Blob([png], { type: "image/png" }), "teste.png");
  const r = await api("POST", "/api/verify/image", form, true);
  assert.equal(r.status, 200, r.text);
  const score = r.json.aiDetection && r.json.aiDetection.score;
  assert.ok(typeof score === "number" && score >= 0 && score <= 1, `bad score: ${score}`);
  assert.equal(r.json.techniques.length, 22);
});
