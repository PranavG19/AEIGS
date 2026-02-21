const express = require("express");
const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const http = require("http");
const ejs = require("ejs");
const serialize = require("node-serialize");
const Database = require("better-sqlite3");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const db = new Database(":memory:");
db.exec(`
  CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    email TEXT NOT NULL,
    ssn TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user'
  );
  INSERT INTO users (id, username, password, email, ssn, role) VALUES
    (1, 'admin', 'admin', 'admin@example.com', '123-45-6789', 'admin'),
    (2, 'alice', 'password123', 'alice@example.com', '987-65-4321', 'user'),
    (3, 'bob', 'hunter2', 'bob@example.com', '555-12-3456', 'user');
`);

// GET /health
app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

// GET /openapi.json
app.get("/openapi.json", (_req, res) => {
  const spec = JSON.parse(
    fs.readFileSync(path.join(__dirname, "openapi.json"), "utf-8")
  );
  res.json(spec);
});

// GET /api/users?id= -- SQL Injection
app.get("/api/users", (req, res) => {
  const id = req.query.id;
  if (!id) {
    return res.status(400).json({ error: "id parameter required" });
  }
  try {
    const sql = "SELECT id, username, email FROM users WHERE id = " + id;
    const rows = db.prepare(sql).all();
    res.json({ users: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/search?q= -- Cross-Site Scripting (reflected XSS)
app.get("/api/search", (req, res) => {
  const q = req.query.q || "";
  res.set("Content-Type", "text/html");
  res.send(`<html><body><h1>Search Results</h1><p>You searched for: ${q}</p><p>No results found.</p></body></html>`);
});

// GET /api/exec?cmd= -- Command Injection
app.get("/api/exec", (req, res) => {
  const cmd = req.query.cmd;
  if (!cmd) {
    return res.status(400).json({ error: "cmd parameter required" });
  }
  try {
    const output = execSync(cmd, { encoding: "utf-8", timeout: 5000 });
    res.json({ output: output });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/files?path= -- Path Traversal
app.get("/api/files", (req, res) => {
  const filePath = req.query.path;
  if (!filePath) {
    return res.status(400).json({ error: "path parameter required" });
  }
  try {
    const content = fs.readFileSync(filePath, "utf-8");
    res.type("text/plain").send(content);
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
});

// GET /api/fetch?url= -- SSRF
app.get("/api/fetch", (req, res) => {
  const url = req.query.url;
  if (!url) {
    return res.status(400).json({ error: "url parameter required" });
  }
  http.get(url, (upstream) => {
    let data = "";
    upstream.on("data", (chunk) => { data += chunk; });
    upstream.on("end", () => {
      res.json({ status: upstream.statusCode, body: data });
    });
  }).on("error", (err) => {
    res.status(500).json({ error: err.message });
  });
});

// GET /api/render?template= -- SSTI (Server-Side Template Injection)
app.get("/api/render", (req, res) => {
  const template = req.query.template || "Hello, World!";
  try {
    const rendered = ejs.render(template);
    res.send(rendered);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/login -- Broken Authentication (hardcoded creds, no rate limit)
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  if (username === "admin" && password === "admin") {
    return res.json({ token: "static-jwt-token-not-signed", role: "admin" });
  }
  res.status(401).json({ error: "Invalid credentials" });
});

// GET /api/profile?user_id= -- Broken Authorization / IDOR
app.get("/api/profile", (req, res) => {
  const userId = req.query.user_id;
  if (!userId) {
    return res.status(400).json({ error: "user_id parameter required" });
  }
  const sql = "SELECT id, username, email, role FROM users WHERE id = ?";
  const user = db.prepare(sql).get(Number(userId));
  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }
  res.json({ profile: user });
});

// GET /api/config -- Security Misconfiguration
app.get("/api/config", (_req, res) => {
  res.json({
    debug: true,
    environment: "development",
    database: "sqlite::memory:",
    default_admin_password: "admin",
    secret_key: "super-secret-key-12345",
    stack_trace: new Error("debug trace").stack,
    node_env: process.env.NODE_ENV || "not set",
    versions: process.versions,
  });
});

// GET /api/users/export -- Sensitive Data Exposure (PII in plaintext)
app.get("/api/users/export", (_req, res) => {
  const rows = db.prepare("SELECT * FROM users").all();
  res.json({ users: rows });
});

// POST /api/deserialize -- Insecure Deserialization
app.post("/api/deserialize", (req, res) => {
  const payload = req.body.data;
  if (!payload) {
    return res.status(400).json({ error: "data field required in body" });
  }
  try {
    const obj = serialize.unserialize(payload);
    res.json({ result: obj });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/redirect?url= -- Open Redirect
app.get("/api/redirect", (req, res) => {
  const url = req.query.url;
  if (!url) {
    return res.status(400).json({ error: "url parameter required" });
  }
  res.redirect(url);
});

// GET /api/header?name=&value= -- Header Injection
app.get("/api/header", (req, res) => {
  const name = req.query.name;
  const value = req.query.value;
  if (!name || !value) {
    return res.status(400).json({ error: "name and value parameters required" });
  }
  res.set(name, value);
  res.json({ message: "Header set", header: name, value: value });
});

// GET /api/log?msg= -- CRLF Injection
app.get("/api/log", (req, res) => {
  const msg = req.query.msg;
  if (!msg) {
    return res.status(400).json({ error: "msg parameter required" });
  }
  res.set("X-Log-Message", msg);
  res.json({ logged: msg });
});

// GET /api/submit?input= -- Insufficient Input Validation
app.get("/api/submit", (req, res) => {
  const input = req.query.input;
  if (input === undefined || input === null) {
    return res.status(400).json({ error: "input parameter required" });
  }
  res.json({
    accepted: true,
    input: input,
    length: input.length,
    processed: true,
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Vulnerable app listening on http://0.0.0.0:${PORT}`);
});
