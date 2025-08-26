// Import Express.js
import express from "express";
import crypto from "crypto";

// Create an Express app
const app = express();

// Middleware to parse JSON bodies
app.use(express.json());

// Set port and verify_token
const port = process.env.PORT || 3000;
const verifyToken = process.env.VERIFY_TOKEN;
const WA_APP_SECRET   = process.env.WA_APP_SECRET;
const CAMUNDA_WEBHOOK_URL = process.env.CAMUNDA_WEBHOOK_URL;
const CAMUNDA_BASIC_USER = process.env.CAMUNDA_BASIC_USER;
const CAMUNDA_BASIC_PASS = process.env.CAMUNDA_BASIC_PASS;
const log = {
  info: (...a) => LOG_LEVEL !== "silent" && console.log(...a),
  debug: (...a) => (LOG_LEVEL === "debug") && console.log(...a),
  warn: (...a) => console.warn(...a),
  error: (...a) => console.error(...a)
};
const LOG_LEVEL = (process.env.LOG_LEVEL || "info").toLowerCase();

if (!WA_APP_SECRET || !CAMUNDA_WEBHOOK_URL || !CAMUNDA_BASIC_PASS) {
  console.error("Missing required env vars. Please set WA_APP_SECRET, CAMUNDA_WEBHOOK_URL, CAMUNDA_BASIC_PASS.");
  process.exit(1);
}

function verifyMetaSignature(req) {
  const sig = req.headers["x-hub-signature-256"];
  if (!sig || !WA_APP_SECRET) return false;
  const body = JSON.stringify(req.body);
  const expected = "sha256=" + crypto.createHmac("sha256", WA_APP_SECRET).update(body).digest("hex");
  try {
    return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
  } catch {
    return false;
  }
}

function extractInbound(body) {
  const change = body?.entry?.[0]?.changes?.[0];
  const msg = change?.value?.messages?.[0];
  if (!msg) return null; // could be a status update (delivery/read)

  // Phone normally lacks '+'
  const phone = msg.from?.startsWith("+") ? msg.from : `+${msg.from}`;

  let text = "";
  switch (msg.type) {
    case "text":
      text = msg.text?.body ?? "";
      break;
    case "button":
      text = msg.button?.text ?? msg.button?.payload ?? "";
      break;
    case "interactive":
      text =
        msg.interactive?.button_reply?.title ??
        msg.interactive?.button_reply?.id ??
        msg.interactive?.list_reply?.title ??
        msg.interactive?.list_reply?.id ?? "";
      break;
    default:
      text = `[${msg.type} received]`;
  }
  return {
    phone,
    text,
    waMessageId: msg.id,
    timestamp: msg.timestamp,
    // If you want the raw WhatsApp message too, uncomment:
    // raw: msg
  };
}

// Route for GET requests
app.get('/', (req, res) => {
  const { 'hub.mode': mode, 'hub.challenge': challenge, 'hub.verify_token': token } = req.query;

  if (mode === 'subscribe' && token === verifyToken) {
    console.log('WEBHOOK VERIFIED');
    res.status(200).send(challenge);
  } else {
    res.status(403).end();
  }
});

// Route for POST requests
app.post('/', async (req, res) => {
  if (!verifyMetaSignature(req)) {
    log.warn("Invalid or missing X-Hub-Signature-256");
    return res.sendStatus(401);
  }
  const timestamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
  console.log(`\n\nWebhook received ${timestamp}\n`);
  console.log(JSON.stringify(req.body, null, 2));
  res.sendStatus(200);
  const inbound = extractInbound(req.body);
  if (!inbound) {
    log.debug("Non-message event received (likely status).");
    return;
  }
  try {
    const basic = Buffer.from(`${CAMUNDA_BASIC_USER}:${CAMUNDA_BASIC_PASS}`).toString("base64");
    const r = await fetch(CAMUNDA_WEBHOOK_URL, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "authorization": `Basic ${basic}`
      },
      body: JSON.stringify(inbound)
    });

    if (!r.ok) {
      const t = await r.text().catch(() => "");
      log.error("Forward to Camunda failed:", r.status, t);
    } else {
      log.info("Forwarded to Camunda:", inbound.phone, inbound.text);
    }
  } catch (e) {
    log.error("Error forwarding to Camunda:", e);
  }
  
});

app.get("/healthz", (_req, res) => res.status(200).send("ok"));

// Start the server
app.listen(port, () => {
  console.log(`\nListening on port ${port}\n`);
});
