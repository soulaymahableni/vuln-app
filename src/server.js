// TP10 – vuln-app corrigée.
// Chaque bloc [FIX] corrige une faille détectée par Semgrep, CodeQL, npm audit ou Gitleaks.
const express = require("express");
const { execFile } = require("child_process");
const sqlite3 = require("sqlite3");
const jwt = require("jsonwebtoken");
const config = require("./config");

// API JSON sans cookie de session (le JWT est envoyé explicitement) : le CSRF ne s'applique pas.
// Risque accepté et documenté dans le README.
const app = express(); // nosemgrep: express-check-csurf-middleware-usage
app.disable("x-powered-by");
app.use(express.json({ limit: "10kb" }));

const db = new sqlite3.Database(":memory:");
db.serialize(() => {
  db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, role TEXT)");
  db.run("INSERT INTO users (name, role) VALUES ('alice', 'admin'), ('bob', 'user')");
});

// [FIX] Injection SQL : requête paramétrée, la valeur n'est jamais concaténée dans le SQL.
//       Le message d'erreur SQL n'est plus renvoyé au client.
app.get("/users", (req, res) => {
  const name = String(req.query.name ?? "");
  db.all("SELECT id, name FROM users WHERE name = ?", [name], (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: "INTERNAL_ERROR" });
    }
    return res.json(rows);
  });
});

// [FIX] Injection de commande : pas de shell (execFile + tableau d'arguments)
//       et validation stricte de l'hôte : lettres, chiffres, "." et "-", 253 caractères max,
//       premier caractère alphanumérique (donc jamais une option "-xxx" passée à ping).
//       Expression simple, sans quantificateurs imbriqués (pas de ReDoS).
const HOST_RE = /^[A-Za-z0-9][A-Za-z0-9.-]*$/;

function isValidHost(host) {
  return host.length <= 253 && HOST_RE.test(host) && !host.includes("..");
}

app.get("/ping", (req, res) => {
  const host = String(req.query.host ?? "");
  if (!isValidHost(host)) {
    return res.status(400).json({ error: "INVALID_HOST" });
  }
  execFile("ping", ["-c", "1", "-W", "2", host], { timeout: 5000 }, (err, stdout) => {
    if (err) {
      return res.status(502).json({ error: "PING_FAILED" });
    }
    return res.type("text").send(stdout);
  });
});

// [FIX] XSS réfléchi : réponse JSON, le navigateur n'interprète pas le contenu comme du HTML.
app.get("/hello", (req, res) => {
  const name = String(req.query.name ?? "").slice(0, 100);
  res.json({ message: `Bonjour ${name}` });
});

// [FIX] Prototype pollution : lodash mis à jour ET plus de merge récursif d'un objet client.
//       Seuls les champs attendus, de type string, sont recopiés dans un objet sans prototype.
const ALLOWED_SETTINGS = ["theme", "language"];

app.post("/settings", (req, res) => {
  const body = req.body && typeof req.body === "object" ? req.body : {};
  const settings = Object.create(null);
  for (const key of ALLOWED_SETTINGS) {
    if (typeof body[key] === "string" && body[key].length <= 50) {
      settings[key] = body[key];
    }
  }
  res.json(settings);
});

// [FIX] JWT : secret lu dans l'environnement, algorithme fixé et expiration d'une heure.
app.post("/login", (req, res) => {
  const user = typeof req.body?.user === "string" ? req.body.user.slice(0, 100) : "";
  if (!user) {
    return res.status(400).json({ error: "USER_REQUIRED" });
  }
  const token = jwt.sign({ user, role: "user" }, config.jwt_secret, {
    algorithm: "HS256",
    expiresIn: "1h",
  });
  return res.json({ token });
});

app.listen(config.port, () => console.log(`vuln-app écoute sur ${config.port}`));
