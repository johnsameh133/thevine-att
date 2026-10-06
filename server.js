"use strict";

const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const PORT = Number(process.env.PORT) || 3000;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const WEBHOOK_URL = process.env.WEBHOOK_URL;
const TRUST_PROXY = process.env.TRUST_PROXY === "true";

const missing = ["ADMIN_USERNAME", "ADMIN_PASSWORD", "WEBHOOK_URL"].filter((k) => !process.env[k]);
if (missing.length) {
  console.error(`Missing required environment variables: ${missing.join(", ")}`);
  process.exit(1);
}

try {
  const u = new URL(WEBHOOK_URL);
  if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error("bad protocol");
} catch {
  console.error("WEBHOOK_URL must be a valid http(s) URL.");
  process.exit(1);
}

let SESSION_SECRET = process.env.SESSION_SECRET;
if (!SESSION_SECRET) {
  SESSION_SECRET = crypto.randomBytes(32).toString("hex");
  console.warn("SESSION_SECRET is not set: using a random one. Admins will be signed out on every restart.");
}

const COOKIE_NAME = "vine_session";
const SESSION_MAX_AGE_SEC = 30 * 24 * 60 * 60;
const WEBHOOK_TIMEOUT_MS = 10000;
const MAX_BODY_BYTES = 4096;
const LOGIN_MAX_FAILURES = 10;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;

const PUBLIC_DIR = path.join(__dirname, "public");
const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
};

// ---------- auth helpers ----------

const sha256 = (s) => crypto.createHash("sha256").update(String(s)).digest();
const safeEqual = (a, b) => crypto.timingSafeEqual(sha256(a), sha256(b));

// Changes whenever the admin credentials change, so old sessions stop working.
const credentialFingerprint = crypto
  .createHmac("sha256", SESSION_SECRET)
  .update(`${ADMIN_USERNAME}\n${ADMIN_PASSWORD}`)
  .digest("hex")
  .slice(0, 16);

function hmac(data) {
  return crypto.createHmac("sha256", SESSION_SECRET).update(data).digest();
}

function createSessionToken() {
  const body = Buffer.from(
    JSON.stringify({ exp: Math.floor(Date.now() / 1000) + SESSION_MAX_AGE_SEC, c: credentialFingerprint })
  ).toString("base64url");
  return `${body}.${hmac(body).toString("base64url")}`;
}

function verifySessionToken(token) {
  if (!token) return false;
  const [body, mac] = token.split(".");
  if (!body || !mac) return false;
  const given = Buffer.from(mac, "base64url");
  const expected = hmac(body);
  if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) return false;
  try {
    const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    return payload.c === credentialFingerprint && payload.exp > Date.now() / 1000;
  } catch {
    return false;
  }
}

function parseCookies(header) {
  const out = {};
  for (const part of (header || "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

const isAuthed = (req) => verifySessionToken(parseCookies(req.headers.cookie)[COOKIE_NAME]);

const isSecureRequest = (req) => Boolean(req.socket.encrypted) || req.headers["x-forwarded-proto"] === "https";

function sessionCookie(req, value, maxAge) {
  const parts = [`${COOKIE_NAME}=${value}`, "Path=/", `Max-Age=${maxAge}`, "HttpOnly", "SameSite=Strict"];
  if (isSecureRequest(req)) parts.push("Secure");
  return parts.join("; ");
}

// ---------- login rate limit ----------

const failures = new Map();

function clientIp(req) {
  if (TRUST_PROXY) {
    const fwd = req.headers["x-forwarded-for"];
    if (fwd) return String(fwd).split(",")[0].trim();
  }
  return req.socket.remoteAddress || "unknown";
}

function isLockedOut(ip) {
  const entry = failures.get(ip);
  if (!entry) return false;
  if (entry.resetAt < Date.now()) {
    failures.delete(ip);
    return false;
  }
  return entry.count >= LOGIN_MAX_FAILURES;
}

function recordFailure(ip) {
  const entry = failures.get(ip);
  if (!entry || entry.resetAt < Date.now()) {
    failures.set(ip, { count: 1, resetAt: Date.now() + LOGIN_WINDOW_MS });
  } else {
    entry.count += 1;
  }
}

setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of failures) if (entry.resetAt < now) failures.delete(ip);
}, 60 * 1000).unref();

// ---------- http helpers ----------

function setSecurityHeaders(req, res) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "camera=(self), microphone=(), geolocation=()");
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; " +
      "media-src 'self' blob:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
  );
  if (isSecureRequest(req)) res.setHeader("Strict-Transport-Security", "max-age=31536000");
}

function sendJson(res, status, data, extraHeaders = {}) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
    "Cache-Control": "no-store",
    ...extraHeaders,
  });
  res.end(body);
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    if (!/^application\/json\b/i.test(req.headers["content-type"] || "")) {
      return reject(Object.assign(new Error("Content-Type must be application/json"), { status: 415 }));
    }
    let size = 0;
    const chunks = [];
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(Object.assign(new Error("Request body too large"), { status: 413 }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}"));
      } catch {
        reject(Object.assign(new Error("Invalid JSON"), { status: 400 }));
      }
    });
    req.on("error", reject);
  });
}

// ---------- api handlers ----------

async function handleLogin(req, res) {
  const ip = clientIp(req);
  if (isLockedOut(ip)) return sendJson(res, 429, { error: "Too many attempts. Try again later." });

  const body = await readJson(req);
  const userOk = safeEqual(body.username ?? "", ADMIN_USERNAME);
  const passOk = safeEqual(body.password ?? "", ADMIN_PASSWORD);

  if (!(userOk && passOk)) {
    recordFailure(ip);
    return sendJson(res, 401, { error: "Invalid username or password." });
  }

  failures.delete(ip);
  sendJson(res, 200, { ok: true }, { "Set-Cookie": sessionCookie(req, createSessionToken(), SESSION_MAX_AGE_SEC) });
}

async function handleScan(req, res) {
  if (!isAuthed(req)) return sendJson(res, 401, { error: "Not signed in." });

  const { name, date, time } = await readJson(req);
  const valid =
    typeof name === "string" &&
    name.trim().length > 0 &&
    name.length <= 200 &&
    typeof date === "string" &&
    /^\d{1,2}\/\d{1,2}\/\d{4}$/.test(date) &&
    typeof time === "string" &&
    /^\d{2}:\d{2}:\d{2}$/.test(time);
  if (!valid) return sendJson(res, 400, { error: "Invalid scan data." });

  const payload = { name: name.trim(), [date]: "1", time };

  try {
    const response = await fetch(WEBHOOK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(WEBHOOK_TIMEOUT_MS),
    });
    await response.body?.cancel();

    if (response.status === 200) return sendJson(res, 200, { ok: true });
    console.error(`Webhook responded with status ${response.status}`);
    return sendJson(res, 502, { ok: false, error: `Webhook responded with status ${response.status}` });
  } catch (err) {
    console.error(`Webhook request failed: ${err.name}: ${err.message}`);
    const timedOut = err.name === "TimeoutError";
    return sendJson(res, 502, { ok: false, error: timedOut ? "Webhook timed out" : "Could not reach webhook" });
  }
}

async function handleApi(req, res, pathname) {
  if (pathname === "/api/session" && req.method === "GET") {
    return sendJson(res, 200, { authed: isAuthed(req) });
  }
  if (pathname === "/api/login" && req.method === "POST") return handleLogin(req, res);
  if (pathname === "/api/logout" && req.method === "POST") {
    return sendJson(res, 200, { ok: true }, { "Set-Cookie": sessionCookie(req, "", 0) });
  }
  if (pathname === "/api/scan" && req.method === "POST") return handleScan(req, res);
  return sendJson(res, 404, { error: "Not found" });
}

// ---------- static files ----------

function serveStatic(req, res, pathname) {
  let rel;
  try {
    rel = decodeURIComponent(pathname);
  } catch {
    res.writeHead(400);
    return res.end("Bad request");
  }
  if (rel === "/") rel = "/index.html";

  const file = path.join(PUBLIC_DIR, rel);
  if (!file.startsWith(PUBLIC_DIR + path.sep)) {
    res.writeHead(404);
    return res.end("Not found");
  }

  fs.stat(file, (err, stat) => {
    if (err || !stat.isFile()) {
      res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      return res.end("Not found");
    }
    const vendor = rel.startsWith("/vendor/");
    res.writeHead(200, {
      "Content-Type": MIME[path.extname(file).toLowerCase()] || "application/octet-stream",
      "Content-Length": stat.size,
      "Cache-Control": vendor ? "public, max-age=86400" : "no-cache",
    });
    if (req.method === "HEAD") return res.end();
    fs.createReadStream(file).pipe(res);
  });
}

// ---------- server ----------

const server = http.createServer(async (req, res) => {
  setSecurityHeaders(req, res);
  const { pathname } = new URL(req.url, "http://localhost");

  try {
    if (pathname === "/healthz") {
      res.writeHead(200, { "Content-Type": "text/plain" });
      return res.end("ok");
    }
    if (pathname.startsWith("/api/")) return await handleApi(req, res, pathname);
    if (req.method !== "GET" && req.method !== "HEAD") {
      res.writeHead(405, { Allow: "GET, HEAD" });
      return res.end();
    }
    return serveStatic(req, res, pathname);
  } catch (err) {
    const status = err.status || 500;
    if (status === 500) console.error(err);
    if (!res.headersSent) sendJson(res, status, { error: status === 500 ? "Internal server error" : err.message });
  }
});

server.listen(PORT, () => console.log(`The Vine Attendance listening on port ${PORT}`));

function shutdown() {
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 5000).unref();
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
