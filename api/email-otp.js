const crypto = require("crypto");

const REDIS_URL = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
const REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;
const RESEND_KEY = process.env.RESEND_API_KEY;
const OTPLY_KEY = process.env.OTPLY_API_KEY;
const OTPLY_URL = process.env.OTPLY_EMAIL_URL || "https://api.adeptcode.in/email-api.php";
const SMTP_HOST = process.env.SMTP_HOST;
const SMTP_PORT = Number(process.env.SMTP_PORT || 465);
const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;
const USE_SMTP = !!(SMTP_HOST && SMTP_USER && SMTP_PASS);
const FROM = process.env.EMAIL_FROM || (USE_SMTP ? "U Cash <" + SMTP_USER + ">" : "U Cash <onboarding@resend.dev>");
const SECRET = process.env.OTP_SECRET;

const TTL = 300;
const COOLDOWN = 30;
const MAX_TRIES = 5;
const HOURLY_EMAIL = 8;
const HOURLY_IP = 20;

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

async function redis(...cmd) {
  const r = await fetch(REDIS_URL, {
    method: "POST",
    headers: { Authorization: "Bearer " + REDIS_TOKEN, "Content-Type": "application/json" },
    body: JSON.stringify(cmd),
  });
  const j = await r.json();
  if (!r.ok || j.error) throw new Error(j.error || "redis " + r.status);
  return j.result;
}

async function counter(key, ttl) {
  const n = await redis("INCR", key);
  if (n === 1) await redis("EXPIRE", key, ttl);
  return n;
}

function hashCode(email, code) {
  return crypto.createHmac("sha256", SECRET).update(email + ":" + code).digest("hex");
}

let transport = null;
async function sendMail(email, code) {
  const subject = code + " is your U Cash verification code";
  const text = "Your U Cash verification code is " + code + ". It expires in 5 minutes.";
  if (OTPLY_KEY) {
    const q = new URLSearchParams({
      api_key: OTPLY_KEY, to: email, type: "custom", subject, message: mailHtml(code), html: "1",
    });
    const r = await fetch(OTPLY_URL + "?" + q.toString());
    const t = await r.text();
    let j = {};
    try { j = JSON.parse(t); } catch (e) {}
    const bad = !r.ok || j.success === false || j.ok === false ||
      /^(error|fail)/i.test(String(j.status || "")) || !!j.error || !!j.error_code;
    if (bad) throw new Error("OTPly " + r.status + " " + t.slice(0, 300));
    return;
  }
  if (USE_SMTP) {
    if (!transport) {
      transport = require("nodemailer").createTransport({
        host: SMTP_HOST, port: SMTP_PORT, secure: SMTP_PORT === 465,
        auth: { user: SMTP_USER, pass: SMTP_PASS },
      });
    }
    await transport.sendMail({ from: FROM, to: email, subject, text, html: mailHtml(code) });
    return;
  }
  const r = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: "Bearer " + RESEND_KEY, "Content-Type": "application/json" },
    body: JSON.stringify({ from: FROM, to: [email], subject, html: mailHtml(code), text }),
  });
  if (!r.ok) throw new Error("Resend " + r.status + " " + (await r.text()));
}

function mailHtml(code) {
  return (
    '<div style="font-family:system-ui,Arial,sans-serif;max-width:420px;margin:auto;padding:24px">' +
    '<h2 style="margin:0 0 8px;color:#4b3bd6">U Cash</h2>' +
    '<p style="color:#333;font-size:15px">Your verification code is:</p>' +
    '<p style="font-size:34px;font-weight:800;letter-spacing:8px;margin:12px 0;color:#111">' + code + "</p>" +
    '<p style="color:#666;font-size:13px">It expires in 5 minutes. If you did not request this, ignore this email.</p>' +
    "</div>"
  );
}

module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Access-Control-Allow-Origin", process.env.ALLOWED_ORIGIN || "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.status(204).end();

  if (req.method === "GET") {
    const check = {
      sender: OTPLY_KEY ? "otply" : USE_SMTP ? "smtp" : RESEND_KEY ? "resend" : "MISSING",
      OTPLY_API_KEY: !!OTPLY_KEY,
      OTP_SECRET: !!SECRET,
      redis_url: !!REDIS_URL,
      redis_token: !!REDIS_TOKEN,
      redis_connection: "not tested",
    };
    if (REDIS_URL && REDIS_TOKEN) {
      try { await redis("PING"); check.redis_connection = "ok"; }
      catch (e) { check.redis_connection = "FAILED: " + String(e.message || e).slice(0, 120); }
    }
    return res.status(200).json(check);
  }
  const reply = (status, body) => res.status(status).json(body);

  if (req.method !== "POST") return reply(405, { ok: false, message: "Method not allowed" });
  if (!REDIS_URL || !REDIS_TOKEN || !(OTPLY_KEY || USE_SMTP || RESEND_KEY) || !SECRET) {
    console.error("email-otp: missing environment variables");
    return reply(500, { ok: false, message: "Email service is not configured" });
  }

  const action = (req.query && req.query.action) || "";
  const body = typeof req.body === "string" ? safeParse(req.body) : req.body || {};
  const email = String(body.email || "").trim().toLowerCase();
  if (!EMAIL_RE.test(email) || email.length > 254) {
    return reply(200, { ok: false, message: "Enter a valid email address" });
  }

  try {
    if (action === "send") {
      const ip = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim() || "unknown";

      const fresh = await redis("SET", "otp:cool:" + email, "1", "EX", COOLDOWN, "NX");
      if (fresh !== "OK") return reply(200, { ok: false, message: "Please wait a few seconds before resending" });

      if ((await counter("otp:hr:e:" + email, 3600)) > HOURLY_EMAIL ||
          (await counter("otp:hr:i:" + ip, 3600)) > HOURLY_IP) {
        return reply(200, { ok: false, message: "Too many requests. Try again in an hour" });
      }

      const code = String(crypto.randomInt(100000, 1000000));
      await redis("SET", "otp:" + email, hashCode(email, code), "EX", TTL);
      await redis("DEL", "otp:tries:" + email);

      try {
        await sendMail(email, code);
      } catch (e) {
        console.error("email-otp: mail error", e && e.message);
        await redis("DEL", "otp:" + email);
        return reply(200, { ok: false, message: "Could not send the email. Try again later" });
      }
      return reply(200, { ok: true });
    }

    if (action === "verify") {
      const otp = String(body.otp || "").replace(/\D/g, "");
      if (otp.length !== 6) return reply(200, { ok: false, message: "Enter the 6-digit code" });

      const tries = await counter("otp:tries:" + email, TTL);
      if (tries > MAX_TRIES) {
        await redis("DEL", "otp:" + email);
        return reply(200, { ok: false, message: "Too many wrong attempts. Request a new code" });
      }

      const stored = await redis("GET", "otp:" + email);
      if (!stored) return reply(200, { ok: false, message: "Code expired. Request a new one" });

      const a = Buffer.from(stored);
      const b = Buffer.from(hashCode(email, otp));
      if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
        return reply(200, { ok: false, message: "Incorrect code" });
      }

      await redis("DEL", "otp:" + email);
      await redis("DEL", "otp:tries:" + email);
      return reply(200, { ok: true });
    }

    return reply(400, { ok: false, message: "Unknown action" });
  } catch (e) {
    console.error("email-otp:", e);
    return reply(500, { ok: false, message: "Server error. Try again" });
  }
};

function safeParse(s) {
  try { return JSON.parse(s); } catch (e) { return {}; }
                             }
