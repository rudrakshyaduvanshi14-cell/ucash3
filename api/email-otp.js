// api/email-otp.js  (CommonJS, no extra packages)
// POST /api/email-otp?action=send    body {email}
// POST /api/email-otp?action=verify  body {email, otp}
// Sends the OTP by email through Gmail SMTP. Needs env: GMAIL_USER, GMAIL_APP_PASSWORD, OTP_SECRET + Upstash Redis (already connected).
// Needs the "nodemailer" package (add it in package.json).
const crypto = require("crypto");
const nodemailer = require("nodemailer");

const RURL = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
const RTOK = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;

async function redis(...cmd) {
  const r = await fetch(RURL, {
    method: "POST",
    headers: { Authorization: "Bearer " + RTOK, "Content-Type": "application/json" },
    body: JSON.stringify(cmd),
  });
  const d = await r.json();
  if (d.error) throw new Error(d.error);
  return d.result;
}
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const cleanEmail = (v) => {
  const e = String(v || "").trim().toLowerCase();
  return e.length <= 120 && EMAIL_RE.test(e) ? e : "";
};
const hashOtp = (email, otp) =>
  crypto.createHash("sha256").update(email + ":" + otp + ":" + (process.env.OTP_SECRET || "change-me")).digest("hex");
const ipOf = (req) => String(req.headers["x-forwarded-for"] || "unknown").split(",")[0].trim();

async function send(req, res) {
  const email = cleanEmail(req.body && req.body.email);
  if (!email) return res.json({ ok: false, message: "Enter a valid email address" });
  if (!process.env.GMAIL_USER || !process.env.GMAIL_APP_PASSWORD)
    return res.json({ ok: false, message: "Email service is not configured" });

  // protect your free quota: 30s cooldown, 6/hour + 10/day per email, 40/hour per IP
  if (!(await redis("SET", "ecd:" + email, "1", "NX", "EX", "30")))
    return res.json({ ok: false, message: "Please wait 30 seconds before resending" });
  const hr = await redis("INCR", "ehr:" + email);
  if (hr === 1) await redis("EXPIRE", "ehr:" + email, "3600");
  if (hr > 6) return res.json({ ok: false, message: "Too many requests. Try again later" });
  const dy = await redis("INCR", "edy:" + email);
  if (dy === 1) await redis("EXPIRE", "edy:" + email, "86400");
  if (dy > 10) return res.json({ ok: false, message: "Daily limit reached for this email" });
  const ip = ipOf(req);
  const ih = await redis("INCR", "eip:" + ip);
  if (ih === 1) await redis("EXPIRE", "eip:" + ip, "3600");
  if (ih > Number(process.env.IP_HOURLY_LIMIT || 40)) return res.json({ ok: false, message: "Too many requests. Try again later" });

  const otp = String(crypto.randomInt(100000, 1000000));
  try {
    const tr = nodemailer.createTransport({
      host: "smtp.gmail.com",
      port: 465,
      secure: true,
      auth: { user: process.env.GMAIL_USER, pass: String(process.env.GMAIL_APP_PASSWORD).replace(/\s/g, "") },
    });
    await tr.sendMail({
      from: '"' + (process.env.MAIL_FROM_NAME || "U Cash") + '" <' + process.env.GMAIL_USER + ">",
      to: email,
      subject: "Your U Cash verification code: " + otp,
      text: "Your U Cash verification code is " + otp + ". It expires in 5 minutes. Do not share it with anyone.",
      html:
        '<div style="font-family:Arial,sans-serif;max-width:420px;margin:auto;padding:24px">' +
        '<h2 style="margin:0 0 12px;color:#1e8a5a">U Cash</h2>' +
        "<p>Your verification code is:</p>" +
        '<p style="font-size:34px;font-weight:700;letter-spacing:8px;margin:12px 0">' + otp + "</p>" +
        '<p style="color:#666">This code expires in 5 minutes. Do not share it with anyone.</p></div>',
    });
  } catch (e) {
    console.error("Gmail SMTP error:", e && e.message); // see Vercel > Logs
    return res.json({ ok: false, message: "Could not send the email. Try again later" });
  }
  await redis("SET", "eotp:" + email, hashOtp(email, otp), "EX", "300");
  await redis("DEL", "etry:" + email);
  return res.json({ ok: true });
}

async function verify(req, res) {
  const email = cleanEmail(req.body && req.body.email);
  const otp = String((req.body && req.body.otp) || "").replace(/\D/g, "");
  if (!email || otp.length !== 6) return res.json({ ok: false, message: "Enter the 6-digit code" });
  const stored = await redis("GET", "eotp:" + email);
  if (!stored) return res.json({ ok: false, message: "Code expired. Tap Resend Code" });
  const t = await redis("INCR", "etry:" + email);
  if (t === 1) await redis("EXPIRE", "etry:" + email, "300");
  if (t > 5) { await redis("DEL", "eotp:" + email); return res.json({ ok: false, message: "Too many wrong attempts. Resend a new code" }); }
  if (hashOtp(email, otp) !== stored) return res.json({ ok: false, message: "Incorrect code" });
  await redis("DEL", "eotp:" + email, "etry:" + email);
  return res.json({ ok: true });
}

module.exports = async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", process.env.ALLOWED_ORIGIN || "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({ ok: false, message: "Method not allowed" });
  try {
    const action = (req.query && req.query.action) || "";
    if (action === "send") return await send(req, res);
    if (action === "verify") return await verify(req, res);
    return res.json({ ok: false, message: "Unknown action" });
  } catch (e) {
    console.error(e);
    return res.json({ ok: false, message: "Could not complete request. Try again" });
  }
};
