// api/whatsapp-otp.js  (CommonJS, no extra packages)
// POST /api/whatsapp-otp?action=send    body {phone}
// POST /api/whatsapp-otp?action=verify  body {phone, otp}
// Sends the OTP on WhatsApp through api.adeptcode.in. Needs env: ADEPT_API_KEY, OTP_SECRET + an Upstash Redis store.
const crypto = require("crypto");

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
const phone10 = (v) => {
  const p = String(v || "").replace(/\D/g, "").slice(-10);
  return /^[6-9][0-9]{9}$/.test(p) ? p : "";
};
const hashOtp = (phone, otp) =>
  crypto.createHash("sha256").update(phone + ":" + otp + ":" + (process.env.OTP_SECRET || "change-me")).digest("hex");
const ipOf = (req) => String(req.headers["x-forwarded-for"] || "unknown").split(",")[0].trim();

async function send(req, res) {
  const phone = phone10(req.body && req.body.phone);
  if (!phone) return res.json({ ok: false, message: "Enter a valid 10-digit mobile number" });
  if (!process.env.ADEPT_API_KEY) return res.json({ ok: false, message: "OTP service is not configured" });

  // protect credits: 30s cooldown, 6/hour + 10/day per number, 40/hour per IP
  if (!(await redis("SET", "pcd:" + phone, "1", "NX", "EX", "30")))
    return res.json({ ok: false, message: "Please wait 30 seconds before resending" });
  const hr = await redis("INCR", "phr:" + phone);
  if (hr === 1) await redis("EXPIRE", "phr:" + phone, "3600");
  if (hr > 6) return res.json({ ok: false, message: "Too many OTP requests. Try again later" });
  const dy = await redis("INCR", "pdy:" + phone);
  if (dy === 1) await redis("EXPIRE", "pdy:" + phone, "86400");
  if (dy > 10) return res.json({ ok: false, message: "Daily OTP limit reached for this number" });
  const ip = ipOf(req);
  const ih = await redis("INCR", "pip:" + ip);
  if (ih === 1) await redis("EXPIRE", "pip:" + ip, "3600");
  if (ih > Number(process.env.IP_HOURLY_LIMIT || 40)) return res.json({ ok: false, message: "Too many requests. Try again later" });

  const otp = String(crypto.randomInt(100000, 1000000));
  const url = new URL(process.env.ADEPT_API_URL || "https://api.adeptcode.in/api.php");
  url.searchParams.set("api_key", process.env.ADEPT_API_KEY);
  url.searchParams.set("mobile", phone);
  url.searchParams.set("otp", otp);

  const r = await fetch(url);
  const d = await r.json().catch(() => ({}));
  if (d.status !== "success") {
    console.error("AdeptCode error:", d.code, d.message); // see Vercel > Logs (e.g. INSUFFICIENT_CREDITS)
    const msg = {
      INVALID_MOBILE: "Enter a valid 10-digit mobile number",
      RATE_LIMIT_MINUTE: "Please wait a minute before trying again",
      RATE_LIMIT_DAY: "Daily OTP limit reached for this number",
    }[d.code] || "Could not send OTP. Try again later";
    return res.json({ ok: false, message: msg });
  }
  await redis("SET", "potp:" + phone, hashOtp(phone, otp), "EX", "300");
  await redis("DEL", "ptry:" + phone);
  return res.json({ ok: true });
}

async function verify(req, res) {
  const phone = phone10(req.body && req.body.phone);
  const otp = String((req.body && req.body.otp) || "").replace(/\D/g, "");
  if (!phone || otp.length !== 6) return res.json({ ok: false, message: "Enter the 6-digit code" });
  const stored = await redis("GET", "potp:" + phone);
  if (!stored) return res.json({ ok: false, message: "OTP expired. Tap Resend Code" });
  const t = await redis("INCR", "ptry:" + phone);
  if (t === 1) await redis("EXPIRE", "ptry:" + phone, "300");
  if (t > 5) { await redis("DEL", "potp:" + phone); return res.json({ ok: false, message: "Too many wrong attempts. Resend a new OTP" }); }
  if (hashOtp(phone, otp) !== stored) return res.json({ ok: false, message: "Incorrect OTP" });
  await redis("DEL", "potp:" + phone, "ptry:" + phone);
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
