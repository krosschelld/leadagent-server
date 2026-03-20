/**
 * BleedLeads — SaaS Server
 * ─────────────────────────────────────────────────────────────
 * Multi-tenant webhook server with two-way AI conversation manager.
 *
 * Required .env vars:
 *   ANTHROPIC_API_KEY, SUPABASE_URL, SUPABASE_SERVICE_KEY,
 *   TWILIO_SID, TWILIO_AUTH, TWILIO_FROM,
 *   SENDGRID_KEY, SENDGRID_FROM,
 *   YELP_WEBHOOK_SECRET,
 *   STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET,
 *   PORT (optional)
 */

require("dotenv").config();
const express   = require("express");
const crypto    = require("crypto");
const bcrypt    = require("bcryptjs");
const jwt       = require("jsonwebtoken");
const Anthropic = require("@anthropic-ai/sdk");
const { createClient } = require("@supabase/supabase-js");
const twilio    = require("twilio");
const sgMail    = require("@sendgrid/mail");
const Stripe    = require("stripe");
const cron      = require("node-cron");
const { pushToCRM } = require("./crm");

// ── Clients ──────────────────────────────────────────────────
const app      = express();
const claude   = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const twilioClient = (process.env.TWILIO_SID && process.env.TWILIO_AUTH)
  ? twilio(process.env.TWILIO_SID, process.env.TWILIO_AUTH) : null;
const stripe = process.env.STRIPE_SECRET_KEY ? Stripe(process.env.STRIPE_SECRET_KEY) : null;
if (process.env.SENDGRID_KEY) sgMail.setApiKey(process.env.SENDGRID_KEY);

// Raw body needed for Stripe webhook verification
app.use("/webhooks/stripe", express.raw({ type: "application/json" }));
app.use(express.json({ limit: "50kb" }));
app.use(express.urlencoded({ extended: true, limit: "50kb" }));

// ── Security headers ──────────────────────────────────────────
app.use((req, res, next) => {
  res.header("X-Content-Type-Options", "nosniff");
  res.header("X-Frame-Options", "DENY");
  res.header("X-XSS-Protection", "1; mode=block");
  res.header("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  res.header("Referrer-Policy", "strict-origin-when-cross-origin");
  next();
});

// ── CORS ─────────────────────────────────────────────────────
const ALLOWED_ORIGINS = [
  "https://bleedleads.com",
  "https://www.bleedleads.com",
  "https://leadagent-dashboard.vercel.app",
  "https://app.bleedleads.com",
  "http://localhost:5173",  // local dev
  "http://localhost:3000",  // local dev
];

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (!origin || ALLOWED_ORIGINS.includes(origin)) {
    res.header("Access-Control-Allow-Origin", origin || "*");
  }
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  if (req.method === "OPTIONS") return res.sendStatus(200);
  next();
});

// ── Global login rate limiter ─────────────────────────────────
const loginAttempts = {};
function loginRateLimit(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress;
  const key = `login:${ip}`;
  const now = Date.now();
  if (!loginAttempts[key]) loginAttempts[key] = { count: 0, resetAt: now + 3600000 };
  if (now > loginAttempts[key].resetAt) loginAttempts[key] = { count: 0, resetAt: now + 3600000 };
  loginAttempts[key].count++;
  if (loginAttempts[key].count > 10) {
    return res.status(429).json({ error: "Too many login attempts. Please wait 30 minutes." });
  }
  next();
}

// ── JWT Auth middleware ───────────────────────────────────────
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token" });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET || "bleedleads-secret");
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

function adminMiddleware(req, res, next) {
  authMiddleware(req, res, () => {
    if (req.user.role !== "admin") return res.status(403).json({ error: "Admin only" });
    next();
  });
}

// ── Helpers ───────────────────────────────────────────────────
function detectService(text) {
  if (/ac|air.?condition|hvac|cool/i.test(text))           return "AC Repair / HVAC";
  if (/water.?heater|hot.?water/i.test(text))              return "Water Heater";
  if (/leak|pipe|plumb|drain|toilet|faucet/i.test(text))   return "Plumbing";
  if (/electric|outlet|circuit|breaker/i.test(text))       return "Electrical";
  if (/furnace|boiler/i.test(text))                        return "Furnace Repair";
  return "General Home Repair";
}

function verifyYelpSignature(req) {
  const sig  = req.headers["x-yelp-signature"] || "";
  const hmac = crypto
    .createHmac("sha256", process.env.YELP_WEBHOOK_SECRET)
    .update(JSON.stringify(req.body))
    .digest("hex");
  return sig === hmac;
}

// Extracts a phone number from any string. Returns null if none found.
function extractPhone(text) {
  const match = text.match(/(\+?1?\s?)?(\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4})/);
  return match ? match[0].trim() : null;
}

// Returns true if a message looks abusive or threatening.
function isAbusive(text) {
  return /fuck|shit|bitch|asshole|idiot|stupid|hate you|kill|threaten/i.test(text);
}

// ── DB helpers ────────────────────────────────────────────────
async function getClientByYelp(yelpAccountId) {
  const { data } = await supabase.from("clients").select("*").eq("yelp_account_id", yelpAccountId).single();
  return data;
}

async function getClientByFacebook(fbPageId) {
  const { data } = await supabase.from("clients").select("*").eq("facebook_page_id", fbPageId).single();
  return data;
}

async function getClientByInstagram(igAccountId) {
  const { data } = await supabase.from("clients").select("*").eq("instagram_account_id", igAccountId).single();
  return data;
}

async function getClientById(id) {
  const { data } = await supabase.from("clients").select("*").eq("id", id).single();
  return data;
}

async function saveLead(lead) {
  const { data, error } = await supabase.from("leads").insert([lead]).select().single();
  if (error) throw new Error(`DB insert: ${error.message}`);
  return data;
}

async function updateLead(id, patch) {
  const { error } = await supabase.from("leads").update(patch).eq("id", id);
  if (error) console.error("DB update:", error.message);
}

async function getLeadByThreadId(threadId) {
  const { data } = await supabase.from("leads").select("*").eq("thread_id", threadId).single();
  return data;
}

async function getAllClients() {
  const { data } = await supabase
    .from("clients").select("*, leads(count)").order("created_at", { ascending: false });
  return data || [];
}

async function getLeadsForClient(clientId, limit = 100) {
  const { data } = await supabase
    .from("leads").select("*").eq("client_id", clientId)
    .order("created_at", { ascending: false }).limit(limit);
  return data || [];
}

async function getAllLeads(limit = 200) {
  const { data } = await supabase
    .from("leads").select("*, clients(name, email)")
    .order("created_at", { ascending: false }).limit(limit);
  return data || [];
}

// ── Conversation DB helpers ───────────────────────────────────

// Save a single message to the conversations table
async function saveMessage(leadId, clientId, platform, threadId, role, message) {
  const { error } = await supabase.from("conversations").insert([{
    lead_id: leadId, client_id: clientId, platform, thread_id: threadId, role, message,
  }]);
  if (error) console.error("saveMessage error:", error.message);
}

// Load all messages for a thread in chronological order
async function loadConversationHistory(threadId) {
  const { data } = await supabase
    .from("conversations").select("role, message")
    .eq("thread_id", threadId).order("created_at", { ascending: true });
  return data || [];
}

// Schedule all 4 follow-up attempts for a lead with no phone number
async function scheduleFollowUps(leadId, clientId, threadId, platform) {
  const now = new Date();
  const attempts = [
    { attempt: 1, fire_at: new Date(now.getTime() + 2  * 60 * 1000) },           // 2 minutes
    { attempt: 2, fire_at: new Date(now.getTime() + 10 * 60 * 1000) },           // 10 minutes
    { attempt: 3, fire_at: new Date(now.getTime() + 60 * 60 * 1000) },           // 1 hour
    { attempt: 4, fire_at: new Date(now.getTime() + 24 * 60 * 60 * 1000) },      // next day
  ];
  const rows = attempts.map(a => ({
    lead_id: leadId, client_id: clientId, thread_id: threadId,
    platform, attempt: a.attempt, fire_at: a.fire_at.toISOString(),
  }));
  const { error } = await supabase.from("follow_up_queue").insert(rows);
  if (error) console.error("scheduleFollowUps error:", error.message);
}

// Cancel all pending follow-ups for a lead (called when phone number is collected)
async function cancelFollowUps(leadId) {
  const { error } = await supabase
    .from("follow_up_queue").update({ cancelled: true })
    .eq("lead_id", leadId).eq("sent", false);
  if (error) console.error("cancelFollowUps error:", error.message);
}

// ── Subscription check ────────────────────────────────────────
function isSubscriptionActive(client) {
  if (client.subscription_status === "active") return true;
  if (client.subscription_status === "trial") {
    return new Date(client.trial_ends_at) > new Date();
  }
  return false;
}

// ── AI helpers ────────────────────────────────────────────────

// System prompt used for every conversation turn
function buildSystemPrompt(client, lead) {
  return `You are a friendly AI assistant for "${client.ai_persona || client.name}", a home services company.
You are having a text conversation with a potential customer on ${lead.source}.

YOUR ONLY JOB is to:
1. Acknowledge their home service issue with warmth and empathy
2. Confirm the company can help
3. Naturally collect their phone number if you don't have it yet
4. Once you have their phone number, let them know someone will be calling them shortly

STRICT RULES:
- Only discuss topics related to their home service issue, contact info, or scheduling
- If asked anything unrelated (weather, general advice, politics, anything off-topic), warmly redirect: "I'm just here to help get your ${lead.service} sorted — what's the best number to reach you?"
- Never answer general knowledge questions
- Keep responses short — 2 to 3 sentences maximum
- Sound like a real human, never robotic or corporate
- Never mention you are an AI
- If the customer seems to be in an emergency situation, reflect urgency in your tone

CURRENT LEAD INFO:
- Name: ${lead.name}
- Service needed: ${lead.service}
- Original message: "${lead.message}"
- Phone collected: ${lead.phone_collected ? "YES — " + lead.phone : "NO — still needed"}`;
}

// Generate the very first reply to a new lead
async function generateFirstReply(lead, client) {
  const hasPhone = !!(lead.phone);
  const systemPrompt = buildSystemPrompt(client, lead);

  const userMessage = hasPhone
    ? `Generate a warm first reply. The customer already provided their phone number (${lead.phone}). Acknowledge their issue and let them know someone will be calling them shortly. Do NOT ask for their number again.`
    : `Generate a warm first reply. Acknowledge their ${lead.service} issue, confirm you can help, and naturally ask for their phone number. Do not be pushy about it.`;

  const msg = await claude.messages.create({
    model: "claude-sonnet-4-6",
    max_tokens: 150,
    system: systemPrompt,
    messages: [{ role: "user", content: userMessage }],
  });
  return msg.content[0].text;
}

// Generate a reply in an ongoing conversation
async function generateConversationReply(lead, client, history) {
  const systemPrompt = buildSystemPrompt(client, lead);

  // Convert stored history to Anthropic message format
  const messages = history.map(h => ({ role: h.role, content: h.content || h.message }));

  const msg = await claude.messages.create({
    model: "claude-sonnet-4-6",
    max_tokens: 150,
    system: systemPrompt,
    messages,
  });
  return msg.content[0].text;
}

// Generate a follow-up message based on which attempt it is
async function generateFollowUpMessage(lead, client, attemptNumber) {
  const systemPrompt = buildSystemPrompt(client, lead);

  const attemptContext = {
    1: "The customer hasn't responded in 2 minutes. Send a gentle follow-up assuming they got busy. Keep it very short and natural.",
    2: "The customer still hasn't responded after 10 minutes. Try a slightly different angle. Still warm, not pushy.",
    3: "The customer hasn't responded in an hour. This is your last chase attempt. Keep it brief and leave the door open.",
    4: "It has been a full day. Do NOT chase for their phone number. Simply check in to see if they got their issue sorted out. Be genuinely warm, not salesy.",
  };

  const msg = await claude.messages.create({
    model: "claude-sonnet-4-6",
    max_tokens: 100,
    system: systemPrompt,
    messages: [{ role: "user", content: attemptContext[attemptNumber] }],
  });
  return msg.content[0].text;
}

// Generate the contractor alert when a phone number is finally collected
async function generateClientAlert(lead, client) {
  const msg = await claude.messages.create({
    model: "claude-sonnet-4-6",
    max_tokens: 400,
    system: `Generate a lead alert for a home services business owner. Return ONLY valid JSON, no markdown.
Keys: sms (under 160 chars), emailSubject, emailBody (4-6 lines), urgency ("emergency"|"same-day"|"standard").
If urgency is emergency, start emailSubject with EMERGENCY LEAD and make the tone urgent.`,
    messages: [{
      role: "user",
      content: `Business: ${client.name}\nLead: ${lead.name} | Phone: ${lead.phone} | Source: ${lead.source} | Service: ${lead.service}\nOriginal message: "${lead.message}"`,
    }],
  });
  try {
    return JSON.parse(msg.content[0].text.replace(/```json|```/g, "").trim());
  } catch {
    return {
      sms: `New lead: ${lead.name} | ${lead.phone} | ${lead.service}`,
      emailSubject: `New Lead: ${lead.name} — ${lead.service}`,
      emailBody: `Name: ${lead.name}\nPhone: ${lead.phone}\nService: ${lead.service}\nSource: ${lead.source}\nMessage: ${lead.message}`,
      urgency: "standard",
    };
  }
}

// ── Platform reply senders ────────────────────────────────────
// These will be filled in as each platform API is integrated.
// For now they log the outbound message so the pipeline still runs end-to-end.

async function sendPlatformReply(platform, threadId, message, client) {
  console.log(`[${platform.toUpperCase()}] Sending reply to thread ${threadId}: "${message}"`);

  if (platform === "facebook") {
    // TODO: Graph API reply — implement when Meta app review approved
    // await sendFacebookReply(threadId, message, client.facebook_page_token);
  }

  if (platform === "instagram") {
    // TODO: Graph API reply — implement when Meta app review approved
    // await sendInstagramReply(threadId, message, client.instagram_page_token);
  }

  if (platform === "yelp") {
    // TODO: Yelp partner API reply — implement when partnership approved
    // await sendYelpReply(threadId, message, client.yelp_api_token);
  }

  // Email parsing (Angi, Thumbtack, Google LSA) — coming in Phase 2
  // Placeholder kept for future implementation

  if (platform === "website") {
    // Widget replies are returned directly via HTTP response — nothing to send here
    console.log(`[WIDGET] Reply queued for thread ${threadId}`);
  }
}

// ── Notification helpers ──────────────────────────────────────
async function notifyClient(client, alert) {
  const results = { sms: false, email: false };

  if (twilioClient && client.notify_sms && client.phone) {
    try {
      await twilioClient.messages.create({
        from: process.env.TWILIO_FROM,
        to:   client.phone,
        body: alert.sms,
      });
      results.sms = true;
    } catch (e) {
      console.error(`SMS failed for client ${client.id}:`, e.message);
    }
  }

  if (client.notify_email && client.email && process.env.SENDGRID_KEY) {
    try {
      await sgMail.send({
        to:      client.email,
        from:    process.env.SENDGRID_FROM || "noreply@bleedleads.com",
        subject: alert.emailSubject,
        text:    alert.emailBody,
      });
      results.email = true;
    } catch (e) {
      console.error(`Email failed for client ${client.id}:`, e.message);
    }
  }

  return results;
}

// ── Core pipeline — new lead ──────────────────────────────────
async function handleNewLead(rawLead, client) {
  if (!isSubscriptionActive(client)) {
    console.warn(`[BleedLeads] Client ${client.id} subscription inactive — skipping`);
    return;
  }

  console.log(`[BleedLeads] New lead for "${client.name}" from ${rawLead.source}: ${rawLead.name}`);

  const threadId = rawLead.thread_id || `${rawLead.source}-${Date.now()}`;
  const hasPhone = !!(rawLead.phone);

  // Save lead to DB
  const lead = await saveLead({
    client_id:  client.id,
    source:     rawLead.source,
    name:       rawLead.name,
    phone:      rawLead.phone || null,
    email:      rawLead.email || null,
    message:    rawLead.message,
    service:    detectService(rawLead.message),
    status:     "processing",
    thread_id:  threadId,
    phone_collected:      hasPhone,
    conversation_status:  "active",
    last_message_at:      new Date().toISOString(),
    created_at:           new Date().toISOString(),
  });

  try {
    // Save the customer's opening message to conversation history
    await saveMessage(lead.id, client.id, rawLead.source, threadId, "user", rawLead.message);

    // Generate and send the first reply
    const firstReply = await generateFirstReply(lead, client);
    await sendPlatformReply(rawLead.source, threadId, firstReply, client);
    await saveMessage(lead.id, client.id, rawLead.source, threadId, "assistant", firstReply);

    // FLOW A — phone number already provided
    if (hasPhone) {
      const alert = await generateClientAlert(lead, client);
      const [notified, crmResult] = await Promise.all([
        notifyClient(client, alert),
        pushToCRM(lead, client, firstReply, alert.urgency),
      ]);
      await updateLead(lead.id, {
        status:               "notified",
        ai_reply:             firstReply,
        urgency:              alert.urgency,
        alert_sms:            alert.sms,
        alert_email_subject:  alert.emailSubject,
        alert_email_body:     alert.emailBody,
        conversation_status:  "completed",
        notified_at:          new Date().toISOString(),
        crm_pushed:           crmResult.success,
        crm_lead_id:          crmResult.leadId || null,
      });
      console.log(`[BleedLeads] Lead ${lead.id} — Flow A complete. Phone in hand, client alerted.`);

    // FLOW B — no phone number, schedule follow-ups
    } else {
      await updateLead(lead.id, { status: "awaiting_reply", ai_reply: firstReply });
      await scheduleFollowUps(lead.id, client.id, threadId, rawLead.source);
      console.log(`[BleedLeads] Lead ${lead.id} — Flow B started. Follow-ups scheduled.`);
    }

  } catch (err) {
    console.error(`[BleedLeads] Pipeline error:`, err);
    await updateLead(lead.id, { status: "error", error_message: err.message });
  }
}

// ── Core pipeline — incoming reply from customer ──────────────
async function handleIncomingReply(platform, threadId, customerMessage, pageId) {
  // Find the lead associated with this thread
  const lead = await getLeadByThreadId(threadId);
  if (!lead) {
    console.warn(`[BleedLeads] No lead found for thread ${threadId}`);
    return;
  }

  // Ignore if conversation is already completed or permanently flagged
  if (lead.conversation_status === "completed") return;

  const client = await getClientById(lead.client_id);
  if (!client || !isSubscriptionActive(client)) return;

  console.log(`[BleedLeads] Incoming reply on lead ${lead.id} from ${platform}`);

  // Update last message time
  await updateLead(lead.id, { last_message_at: new Date().toISOString() });

  // ── Abuse detection ───────────────────────────────────────
  if (isAbusive(customerMessage)) {
    const newAbuseCount = (lead.abuse_count || 0) + 1;
    await updateLead(lead.id, { abuse_count: newAbuseCount });

    if (newAbuseCount === 1) {
      // First offence — one calm redirect
      const redirect = `I'm just here to help get your ${lead.service} sorted — happy to help when you're ready.`;
      await sendPlatformReply(platform, threadId, redirect, client);
      await saveMessage(lead.id, client.id, platform, threadId, "user", customerMessage);
      await saveMessage(lead.id, client.id, platform, threadId, "assistant", redirect);
      return;
    }

    if (newAbuseCount >= 2) {
      // Second offence — stop responding, flag the lead, alert contractor
      await updateLead(lead.id, {
        conversation_status: "flagged",
        flagged_reason: "Customer sent abusive messages",
      });
      await cancelFollowUps(lead.id);

      // Alert contractor about the flagged lead
      if (client.notify_email && client.email && process.env.SENDGRID_KEY) {
        await sgMail.send({
          to:      client.email,
          from:    process.env.SENDGRID_FROM || "noreply@bleedleads.com",
          subject: `Flagged Lead: ${lead.name} — Review Recommended`,
          text:    `Lead ${lead.name} from ${lead.source} sent abusive messages and the AI has stopped responding.\n\nOriginal issue: ${lead.service}\nOriginal message: ${lead.message}\n\nYou may want to review this thread.`,
        }).catch(console.error);
      }
      console.log(`[BleedLeads] Lead ${lead.id} flagged for abuse. Client alerted.`);
      return;
    }
  }

  // ── Check if customer provided a phone number ─────────────
  const phone = extractPhone(customerMessage);

  // Save incoming message to history
  await saveMessage(lead.id, client.id, platform, threadId, "user", customerMessage);

  if (phone && !lead.phone_collected) {
    // Phone number just collected — cancel follow-ups, alert contractor
    await cancelFollowUps(lead.id);
    await updateLead(lead.id, {
      phone:               phone,
      phone_collected:     true,
      conversation_status: "completed",
      status:              "notified",
      notified_at:         new Date().toISOString(),
    });

    // Reload lead with updated phone for alert generation
    const updatedLead = { ...lead, phone, phone_collected: true };

    // Send closing message to customer
    const closingMsg = await generateConversationReply(updatedLead, client, [
      { role: "user", content: updatedLead.message },
      { role: "assistant", content: "I can help with that — what is the best number to reach you at?" },
      { role: "user", content: customerMessage },
    ]);
    await sendPlatformReply(platform, threadId, closingMsg, client);
    await saveMessage(lead.id, client.id, platform, threadId, "assistant", closingMsg);

    // Alert the contractor
    const alert = await generateClientAlert(updatedLead, client);
    const [notified, crmResult] = await Promise.all([
      notifyClient(client, alert),
      pushToCRM(updatedLead, client, closingMsg, alert.urgency),
    ]);

    await updateLead(lead.id, {
      ai_reply:             closingMsg,
      urgency:              alert.urgency,
      alert_sms:            alert.sms,
      alert_email_subject:  alert.emailSubject,
      alert_email_body:     alert.emailBody,
      crm_pushed:           crmResult.success,
      crm_lead_id:          crmResult.leadId || null,
    });

    console.log(`[BleedLeads] Lead ${lead.id} — phone collected. Client alerted. SMS:${notified.sms} Email:${notified.email}`);
    return;
  }

  // ── No phone number yet — continue the conversation ───────
  // Reactivate if this lead was previously marked unresponsive
  if (lead.conversation_status === "unresponsive") {
    await updateLead(lead.id, { conversation_status: "active" });
  }

  const history = await loadConversationHistory(threadId);
  const reply   = await generateConversationReply(lead, client, history);
  await sendPlatformReply(platform, threadId, reply, client);
  await saveMessage(lead.id, client.id, platform, threadId, "assistant", reply);
  await updateLead(lead.id, { ai_reply: reply }); // Keep ai_reply current with latest message

  console.log(`[BleedLeads] Lead ${lead.id} — conversation continued, still working on phone number.`);
}

// ── Follow-up cron job ────────────────────────────────────────
// Runs every 60 seconds. Checks for any follow-ups that are due and fires them.
cron.schedule("* * * * *", async () => {
  const now = new Date().toISOString();

  const { data: duejobs, error } = await supabase
    .from("follow_up_queue")
    .select("*")
    .lte("fire_at", now)
    .eq("sent", false)
    .eq("cancelled", false);

  if (error) { console.error("[Cron] follow_up_queue fetch error:", error.message); return; }
  if (!duejobs || duejobs.length === 0) return;

  console.log(`[Cron] ${duejobs.length} follow-up(s) due`);

  for (const job of duejobs) {
    try {
      // Mark as sent immediately to prevent double-firing if cron overlaps
      await supabase.from("follow_up_queue").update({ sent: true }).eq("id", job.id);

      // Get lead and client
      const lead   = await supabase.from("leads").select("*").eq("id", job.lead_id).single().then(r => r.data);
      const client = await getClientById(job.client_id);

      // Skip if lead is no longer active or phone was collected between scheduling and now
      if (!lead || !client) continue;
      if (lead.phone_collected)                               continue;
      if (lead.conversation_status === "flagged")             continue;
      if (lead.conversation_status === "completed")           continue;

      const followUpMsg = await generateFollowUpMessage(lead, client, job.attempt);
      await sendPlatformReply(job.platform, job.thread_id, followUpMsg, client);
      await saveMessage(lead.id, client.id, job.platform, job.thread_id, "assistant", followUpMsg);

      // After attempt 4 (next day check-in) with no response, mark unresponsive
      if (job.attempt === 4) {
        await updateLead(lead.id, { conversation_status: "unresponsive" });
        console.log(`[Cron] Lead ${lead.id} — follow-up sequence complete. Marked unresponsive.`);
      } else {
        console.log(`[Cron] Lead ${lead.id} — follow-up attempt ${job.attempt} sent.`);
      }

    } catch (err) {
      console.error(`[Cron] Error processing follow-up job ${job.id}:`, err.message);
    }
  }
});


// ── Weekly summary email ──────────────────────────────────────
// Runs every Monday at 7am UTC
cron.schedule("0 7 * * 1", async () => {
  console.log("[Weekly] Starting weekly summary emails");

  const { data: clients } = await supabase
    .from("clients")
    .select("*")
    .eq("subscription_status", "active");

  if (!clients || clients.length === 0) return;

  const weekStart = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
  const weekEnd   = new Date().toISOString();

  for (const client of clients) {
    try {
      if (client.weekly_summary === false) continue;
      if (!client.email) continue;

      const { data: leads } = await supabase
        .from("leads")
        .select("*")
        .eq("client_id", client.id)
        .gte("created_at", weekStart)
        .lte("created_at", weekEnd);

      if (!leads || leads.length === 0) continue;

      const total    = leads.length;
      const sent     = leads.filter(l => l.conversation_status === "completed").length;
      const noAnswer = leads.filter(l => l.conversation_status === "unresponsive").length;
      const won      = leads.filter(l => l.won).length;
      const revenue  = leads.filter(l => l.won && l.job_value).reduce((sum, l) => sum + parseFloat(l.job_value), 0);

      const sourceCounts  = leads.reduce((acc, l) => { acc[l.source] = (acc[l.source] || 0) + 1; return acc; }, {});
      const topSource     = Object.entries(sourceCounts).sort((a, b) => b[1] - a[1])[0];
      const topSourceLabel = topSource ? `${topSource[0].charAt(0).toUpperCase() + topSource[0].slice(1)} (${topSource[1]} lead${topSource[1] > 1 ? "s" : ""})` : "N/A";

      let perfMsg = "";
      if (won >= 5)       perfMsg = "Outstanding week — your AI is working hard for you.";
      else if (won >= 2)  perfMsg = "Solid week. Keep calling those leads back fast.";
      else if (sent >= 5) perfMsg = "Lots of leads came in — make sure you are calling them back quickly.";
      else                perfMsg = "Every lead matters. Your AI is answering all of them.";

      const weekLabel = new Date(weekStart).toLocaleDateString("en-US", { month:"short", day:"numeric" }) + " to " + new Date(weekEnd).toLocaleDateString("en-US", { month:"short", day:"numeric" });

      const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head><body style="margin:0;padding:0;background:#0A0A0A;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;"><table width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;margin:0 auto;padding:32px 16px;"><tr><td><table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:32px;"><tr><td style="font-family:'Arial Black',sans-serif;font-size:28px;font-weight:900;letter-spacing:2px;color:#ffffff;">BLEED<span style="color:#D90000;">LEADS</span></td></tr><tr><td style="font-size:13px;color:#555;padding-top:4px;letter-spacing:1px;text-transform:uppercase;">Weekly Summary &mdash; ${weekLabel}</td></tr></table><table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:24px;"><tr><td style="font-size:16px;color:#ccc;line-height:1.6;">Hey ${client.owner_name || client.name},<br>Here is how BleedLeads performed for <strong style="color:#fff;">${client.name}</strong> last week.</td></tr></table><table width="100%" cellpadding="0" cellspacing="0" style="background:#111;border:1px solid #1A1A1A;margin-bottom:24px;"><tr><td style="padding:20px 24px;border-bottom:1px solid #1A1A1A;"><table width="100%" cellpadding="0" cellspacing="0"><tr><td width="50%" style="padding-bottom:16px;"><div style="font-size:11px;color:#555;letter-spacing:2px;text-transform:uppercase;margin-bottom:4px;">Leads Received</div><div style="font-size:36px;font-weight:900;color:#ffffff;font-family:'Arial Black',sans-serif;">${total}</div></td><td width="50%" style="padding-bottom:16px;"><div style="font-size:11px;color:#555;letter-spacing:2px;text-transform:uppercase;margin-bottom:4px;">Sent To You</div><div style="font-size:36px;font-weight:900;color:#10B981;font-family:'Arial Black',sans-serif;">${sent}</div></td></tr><tr><td width="50%"><div style="font-size:11px;color:#555;letter-spacing:2px;text-transform:uppercase;margin-bottom:4px;">Jobs Won</div><div style="font-size:36px;font-weight:900;color:#10B981;font-family:'Arial Black',sans-serif;">${won}</div></td><td width="50%"><div style="font-size:11px;color:#555;letter-spacing:2px;text-transform:uppercase;margin-bottom:4px;">Revenue Logged</div><div style="font-size:36px;font-weight:900;color:#F59E0B;font-family:'Arial Black',sans-serif;">${revenue > 0 ? "$" + revenue.toLocaleString() : "&mdash;"}</div></td></tr></table></td></tr><tr><td style="padding:14px 24px;border-bottom:1px solid #1A1A1A;"><span style="font-size:12px;color:#555;text-transform:uppercase;letter-spacing:1px;">Top Source: </span><span style="font-size:12px;color:#ccc;font-weight:700;">${topSourceLabel}</span></td></tr><tr><td style="padding:14px 24px;"><span style="font-size:12px;color:#555;text-transform:uppercase;letter-spacing:1px;">No Answer: </span><span style="font-size:12px;color:#ccc;">${noAnswer} lead${noAnswer !== 1 ? "s" : ""}</span></td></tr></table><table width="100%" cellpadding="0" cellspacing="0" style="background:#D90000;margin-bottom:24px;"><tr><td style="padding:16px 24px;font-size:14px;color:#fff;font-weight:600;">${perfMsg}</td></tr></table><table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:32px;"><tr><td align="center"><a href="https://app.bleedleads.com" style="display:inline-block;background:#D90000;color:#fff;text-decoration:none;padding:14px 32px;font-size:13px;font-weight:700;letter-spacing:2px;text-transform:uppercase;">View Your Dashboard</a></td></tr></table><table width="100%" cellpadding="0" cellspacing="0"><tr><td style="border-top:1px solid #1A1A1A;padding-top:20px;font-size:11px;color:#333;text-align:center;line-height:1.8;">BleedLeads LLC &mdash; Ogden, UT &mdash; Veteran Owned &amp; Operated<br><a href="https://app.bleedleads.com" style="color:#555;text-decoration:none;">Manage email preferences in your dashboard settings</a></td></tr></table></td></tr></table></body></html>`;

      await sgMail.send({
        to:      client.email,
        from:    process.env.SENDGRID_FROM,
        subject: `Your BleedLeads Weekly Summary — ${weekLabel}`,
        html,
        text: `BleedLeads Weekly Summary for ${client.name}\n\nLeads: ${total} | Sent To You: ${sent} | Jobs Won: ${won} | Revenue: $${revenue}\nTop Source: ${topSourceLabel}\n\n${perfMsg}\n\nView your dashboard: https://app.bleedleads.com`,
      });

      console.log(`[Weekly] Summary sent to ${client.name} (${client.email})`);

    } catch (err) {
      console.error(`[Weekly] Error sending summary to client ${client.id}:`, err.message);
    }
  }

  console.log("[Weekly] Summary emails complete");
});

// ── Webhook routes ────────────────────────────────────────────

// Yelp — new lead
app.post("/webhooks/yelp", async (req, res) => {
  if (process.env.YELP_WEBHOOK_SECRET && !verifyYelpSignature(req)) {
    return res.status(401).json({ error: "Invalid signature" });
  }
  const { event_type, lead: yelpLead, business_id } = req.body;
  if (event_type !== "lead" || !yelpLead) return res.status(200).json({ ok: true });
  res.status(200).json({ ok: true });

  const client = await getClientByYelp(business_id);
  if (!client) return console.warn(`[Yelp] No client found for business_id: ${business_id}`);
  await handleNewLead({
    source:    "yelp",
    name:      yelpLead.name,
    phone:     yelpLead.phone,
    email:     yelpLead.email,
    message:   yelpLead.text || yelpLead.message,
    thread_id: yelpLead.conversation_id || yelpLead.id,
  }, client);
});

// Yelp — incoming customer reply
app.post("/webhooks/yelp/reply", async (req, res) => {
  res.status(200).json({ ok: true });
  const { message, conversation_id, business_id } = req.body;
  if (!message || !conversation_id) return;
  await handleIncomingReply("yelp", conversation_id, message, business_id);
});

// Facebook / Instagram — webhook verification
app.get("/webhooks/meta", (req, res) => {
  const mode      = req.query["hub.mode"];
  const token     = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];
  if (mode === "subscribe" && token === process.env.META_VERIFY_TOKEN) {
    return res.status(200).send(challenge);
  }
  res.status(403).send("Forbidden");
});

// Facebook / Instagram — incoming messages
app.post("/webhooks/meta", async (req, res) => {
  res.status(200).json({ ok: true }); // Always respond fast to Meta
  const body = req.body;
  if (body.object !== "page" && body.object !== "instagram") return;

  for (const entry of (body.entry || [])) {
    const pageId = entry.id;

    for (const event of (entry.messaging || [])) {
      if (!event.message || event.message.is_echo) continue; // Skip echoes of our own messages

      const threadId       = event.sender.id;
      const customerMessage = event.message.text;
      if (!customerMessage) continue;

      // Check if this is a first contact or a reply
      const existingLead = await getLeadByThreadId(threadId);

      if (!existingLead) {
        // Brand new lead — determine platform from object type
        const platform = body.object === "instagram" ? "instagram" : "facebook";
        const client   = platform === "facebook"
          ? await getClientByFacebook(pageId)
          : await getClientByInstagram(pageId);
        if (!client) { console.warn(`[Meta] No client for page ${pageId}`); continue; }

        await handleNewLead({
          source:    platform,
          name:      event.sender.id, // Name resolved via Graph API later
          phone:     null,
          email:     null,
          message:   customerMessage,
          thread_id: threadId,
        }, client);

      } else {
        // Existing thread — route to conversation handler
        const platform = existingLead.source;
        await handleIncomingReply(platform, threadId, customerMessage, pageId);
      }
    }
  }
});

// ── Email parsing — stubbed, coming in Phase 2 ─────────────────

// ── Stripe webhooks ───────────────────────────────────────────
app.post("/webhooks/stripe", async (req, res) => {
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers["stripe-signature"], process.env.STRIPE_WEBHOOK_SECRET);
  } catch (e) {
    return res.status(400).send(`Webhook error: ${e.message}`);
  }

  const sub = event.data.object;

  if (event.type === "customer.subscription.created" || event.type === "customer.subscription.updated") {
    const { data: client } = await supabase.from("clients").select("id").eq("stripe_customer_id", sub.customer).single();
    if (client) {
      await supabase.from("clients").update({
        subscription_status: sub.status === "active" ? "active" : sub.status,
        stripe_sub_id:       sub.id,
        subscribed_at:       sub.status === "active" ? new Date().toISOString() : undefined,
      }).eq("id", client.id);
    }
  }

  if (event.type === "customer.subscription.deleted") {
    const { data: client } = await supabase.from("clients").select("id").eq("stripe_customer_id", sub.customer).single();
    if (client) await supabase.from("clients").update({ subscription_status: "cancelled" }).eq("id", client.id);
  }

  if (event.type === "invoice.payment_failed") {
    const { data: client } = await supabase.from("clients").select("id, email, name").eq("stripe_customer_id", sub.customer).single();
    if (client) {
      await supabase.from("clients").update({ subscription_status: "past_due" }).eq("id", client.id);
      if (process.env.SENDGRID_KEY) {
        await sgMail.send({
          to:      client.email,
          from:    process.env.SENDGRID_FROM || "noreply@bleedleads.com",
          subject: "Action required: Payment failed for BleedLeads",
          text:    `Hi ${client.name},\n\nYour payment failed. Please update your billing details to continue receiving leads.\n\nBleedLeads`,
        }).catch(console.error);
      }
    }
  }

  res.json({ received: true });
});

// ── Auth routes ───────────────────────────────────────────────

// Client self-signup
app.post("/auth/signup", loginRateLimit, async (req, res) => {
  const { name, ownerName, email, phone, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: "name, email, password required" });

  const hash = await bcrypt.hash(password, 10);
  const { data: client, error } = await supabase.from("clients").insert([{
    name, owner_name: ownerName, email, phone, password_hash: hash,
    subscription_status: "trial",
  }]).select().single();

  if (error) return res.status(400).json({ error: error.message });

  if (process.env.STRIPE_SECRET_KEY) {
    try {
      const customer = await stripe.customers.create({ email, name, metadata: { client_id: client.id } });
      await supabase.from("clients").update({ stripe_customer_id: customer.id }).eq("id", client.id);
    } catch (e) {
      console.error("Stripe customer creation failed:", e.message);
    }
  }

  const token = jwt.sign({ id: client.id, role: "client" }, process.env.JWT_SECRET || "bleedleads-secret", { expiresIn: "30d" });
  res.json({ token, client: { id: client.id, name: client.name, email: client.email, phone: client.phone, subscription_status: client.subscription_status, weekly_summary: client.weekly_summary } });
});

// Client login
app.post("/auth/login", loginRateLimit, async (req, res) => {
  const { email, password } = req.body;
  const { data: client } = await supabase.from("clients").select("*").eq("email", email).single();
  if (!client || !(await bcrypt.compare(password, client.password_hash || ""))) {
    return res.status(401).json({ error: "Invalid email or password" });
  }
  const token = jwt.sign({ id: client.id, role: "client" }, process.env.JWT_SECRET || "bleedleads-secret", { expiresIn: "30d" });
  res.json({ token, client: { id: client.id, name: client.name, email: client.email, phone: client.phone, subscription_status: client.subscription_status, weekly_summary: client.weekly_summary } });
});

// Admin login
app.post("/auth/admin", loginRateLimit, (req, res) => {
  const { password } = req.body;
  if (password !== process.env.ADMIN_PASSWORD) return res.status(401).json({ error: "Invalid password" });
  const token = jwt.sign({ role: "admin" }, process.env.JWT_SECRET || "bleedleads-secret", { expiresIn: "7d" });
  res.json({ token });
});

// ── Admin API routes ──────────────────────────────────────────
app.get("/admin/clients", adminMiddleware, async (req, res) => {
  res.json(await getAllClients());
});

app.post("/admin/clients", adminMiddleware, async (req, res) => {
  const { name, ownerName, email, phone, yelpAccountId, facebookPageId, instagramAccountId, subscriptionStatus, aiPersona } = req.body;
  const { data, error } = await supabase.from("clients").insert([{
    name, owner_name: ownerName, email, phone,
    yelp_account_id:      yelpAccountId,
    facebook_page_id:     facebookPageId,
    instagram_account_id: instagramAccountId,
    subscription_status:  subscriptionStatus || "active",
    ai_persona:           aiPersona || name,
  }]).select().single();
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

app.put("/admin/clients/:id", adminMiddleware, async (req, res) => {
  const { data, error } = await supabase.from("clients").update(req.body).eq("id", req.params.id).select().single();
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

app.delete("/admin/clients/:id", adminMiddleware, async (req, res) => {
  await supabase.from("clients").delete().eq("id", req.params.id);
  res.json({ ok: true });
});

app.get("/admin/leads", adminMiddleware, async (req, res) => {
  res.json(await getAllLeads());
});

app.get("/admin/stats", adminMiddleware, async (req, res) => {
  const [{ count: totalClients }, { count: activeClients }, { count: totalLeads }, { count: todayLeads }] = await Promise.all([
    supabase.from("clients").select("*", { count: "exact", head: true }),
    supabase.from("clients").select("*", { count: "exact", head: true }).eq("subscription_status", "active"),
    supabase.from("leads").select("*", { count: "exact", head: true }),
    supabase.from("leads").select("*", { count: "exact", head: true }).gte("created_at", new Date(new Date().setHours(0,0,0,0)).toISOString()),
  ]);
  res.json({ totalClients, activeClients, totalLeads, todayLeads });
});

// ── Client API routes ─────────────────────────────────────────
app.get("/client/me", authMiddleware, async (req, res) => {
  const client = await getClientById(req.user.id);
  if (!client) return res.status(404).json({ error: "Not found" });
  res.json(client);
});

app.get("/client/leads", authMiddleware, async (req, res) => {
  res.json(await getLeadsForClient(req.user.id));
});

app.put("/client/settings", authMiddleware, async (req, res) => {
  const { phone, notifySms, notifyEmail, aiPersona, crmType, crmApiKey, crmLocationId, crmWebhookUrl, crmPipelineId, crmStageId } = req.body;
  const { data, error } = await supabase.from("clients").update({
    phone,
    notify_sms:      notifySms,
    notify_email:    notifyEmail,
    ai_persona:      aiPersona,
    crm_type:        crmType,
    crm_api_key:     crmApiKey,
    crm_location_id: crmLocationId,
    crm_webhook_url: crmWebhookUrl,
    crm_pipeline_id: crmPipelineId,
    crm_stage_id:    crmStageId,
  }).eq("id", req.user.id).select().single();
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

// Stripe checkout
app.post("/client/subscribe", authMiddleware, async (req, res) => {
  const { plan } = req.body;
  const client = await getClientById(req.user.id);
  const priceMap = {
    single:     process.env.STRIPE_PRICE_SINGLE,
    multi:      process.env.STRIPE_PRICE_MULTI,
    regional:   process.env.STRIPE_PRICE_REGIONAL,
  };
  const session = await stripe.checkout.sessions.create({
    customer:             client.stripe_customer_id,
    mode:                 "subscription",
    payment_method_types: ["card"],
    line_items:           [{ price: priceMap[plan], quantity: 1 }],
    success_url:          `${process.env.APP_URL}/dashboard?subscribed=true`,
    cancel_url:           `${process.env.APP_URL}/dashboard?cancelled=true`,
  });
  res.json({ url: session.url });
});

// ── Rate limiting store ───────────────────────────────────────
// In-memory rate limiter. Resets on server restart.
// For production scale, replace with Redis.
const rateLimits = {};

function checkRateLimit(key, maxAttempts, windowMs) {
  const now = Date.now();
  if (!rateLimits[key]) rateLimits[key] = { count: 0, resetAt: now + windowMs };
  if (now > rateLimits[key].resetAt) rateLimits[key] = { count: 0, resetAt: now + windowMs };
  rateLimits[key].count++;
  return rateLimits[key].count <= maxAttempts;
}

function getRateLimitKey(clientId, action) {
  return `${clientId}:${action}:${new Date().toISOString().slice(0, 13)}`; // hourly key
}

function getDailyRateLimitKey(clientId, action) {
  return `${clientId}:${action}:${new Date().toISOString().slice(0, 10)}`; // daily key
}

// ── Business name sanitizer ───────────────────────────────────
const BLOCKED_PROMPT_WORDS = ["ignore", "system", "prompt", "instructions", "assistant", "override", "jailbreak", "disregard", "forget", "pretend", "bypass", "inject"];

function sanitizeBusinessName(name) {
  if (!name || typeof name !== "string") return null;
  // Strip everything except safe characters
  let clean = name.replace(/[^a-zA-Z0-9\s\-'\.&,]/g, "").trim();
  // Enforce max length
  clean = clean.slice(0, 60);
  // Check for prompt injection attempts — log but return generic error
  const lower = clean.toLowerCase();
  for (const word of BLOCKED_PROMPT_WORDS) {
    if (lower.includes(word)) {
      console.warn(`[Security] Blocked prompt injection attempt in business name: "${name}"`);
      return null;
    }
  }
  return clean.length > 0 ? clean : null;
}

// ── Audit logger ──────────────────────────────────────────────
async function logAudit(clientId, action, field, oldValue, newValue, ip) {
  await supabase.from("audit_log").insert([{
    client_id: clientId,
    action,
    field,
    old_value: oldValue ? String(oldValue) : null,
    new_value: newValue ? String(newValue) : null,
    ip_address: ip || null,
  }]).catch(e => console.error("Audit log error:", e.message));
}

// ── Client settings update ────────────────────────────────────
app.put("/client/profile", authMiddleware, async (req, res) => {
  const clientId = req.user.id;
  const ip = req.ip;

  // Rate limit — 10 changes per hour
  if (!checkRateLimit(getRateLimitKey(clientId, "settings"), 10, 60 * 60 * 1000)) {
    return res.status(429).json({ error: "Too many changes. Please wait before trying again." });
  }

  const client = await getClientById(clientId);
  if (!client) return res.status(404).json({ error: "Client not found" });

  const updates = {};
  const { businessName, email, phone, weeklySummary } = req.body;

  // Business name
  if (businessName !== undefined) {
    const clean = sanitizeBusinessName(businessName);
    if (!clean) return res.status(400).json({ error: "Invalid business name. Please use only letters, numbers, and basic punctuation." });
    await logAudit(clientId, "update", "ai_persona", client.ai_persona, clean, ip);
    updates.ai_persona = clean;
    updates.name = clean;
  }

  // Email
  if (email !== undefined) {
    if (!checkRateLimit(getDailyRateLimitKey(clientId, "email_change"), 3, 24 * 60 * 60 * 1000)) {
      return res.status(429).json({ error: "Email can only be changed 3 times per day." });
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) return res.status(400).json({ error: "Invalid email address." });
    // Check not already in use
    const { data: existing } = await supabase.from("clients").select("id").eq("email", email).single();
    if (existing && existing.id !== clientId) return res.status(400).json({ error: "Email already in use." });
    await logAudit(clientId, "update", "email", client.email, email, ip);
    updates.email = email;
  }

  // Phone
  if (phone !== undefined) {
    const cleanPhone = phone.replace(/[^\d\s\-\(\)\+]/g, "").trim();
    if (cleanPhone.replace(/\D/g, "").length < 10) return res.status(400).json({ error: "Invalid phone number." });
    await logAudit(clientId, "update", "phone", client.phone, cleanPhone, ip);
    updates.phone = cleanPhone;
  }

  // Weekly summary preference
  if (weeklySummary !== undefined) {
    updates.weekly_summary = weeklySummary === true || weeklySummary === "true";
  }

  if (Object.keys(updates).length === 0) return res.status(400).json({ error: "No valid fields provided." });

  const { data, error } = await supabase.from("clients").update(updates).eq("id", clientId).select().single();
  if (error) return res.status(400).json({ error: error.message });
  res.json({ ok: true, client: { name: data.name, email: data.email, phone: data.phone } });
});

// ── Password change ───────────────────────────────────────────
app.put("/client/password", authMiddleware, async (req, res) => {
  const clientId = req.user.id;
  const ip = req.ip;

  // Rate limit — 10 attempts per hour, 3 changes per day
  if (!checkRateLimit(getRateLimitKey(clientId, "password_attempt"), 10, 60 * 60 * 1000)) {
    return res.status(429).json({ error: "Too many attempts. Please wait 30 minutes." });
  }
  if (!checkRateLimit(getDailyRateLimitKey(clientId, "password_change"), 3, 24 * 60 * 60 * 1000)) {
    return res.status(429).json({ error: "Password can only be changed 3 times per day." });
  }

  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) return res.status(400).json({ error: "Current and new password required." });
  if (newPassword.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters." });
  if (!/\d/.test(newPassword)) return res.status(400).json({ error: "Password must include at least one number." });

  const client = await getClientById(clientId);
  if (!client) return res.status(404).json({ error: "Client not found" });

  const valid = await bcrypt.compare(currentPassword, client.password_hash || "");
  if (!valid) return res.status(401).json({ error: "Current password is incorrect." });

  const hash = await bcrypt.hash(newPassword, 10);
  const { error } = await supabase.from("clients").update({ password_hash: hash }).eq("id", clientId);
  if (error) return res.status(400).json({ error: error.message });

  await logAudit(clientId, "password_change", "password_hash", null, null, ip);
  res.json({ ok: true });
});

// ── Subscription cancellation ─────────────────────────────────
app.post("/client/cancel", authMiddleware, async (req, res) => {
  const clientId = req.user.id;
  const ip = req.ip;
  const { confirmation } = req.body;

  if (confirmation !== "CANCEL") {
    return res.status(400).json({ error: "Type CANCEL to confirm cancellation." });
  }

  const client = await getClientById(clientId);
  if (!client) return res.status(404).json({ error: "Client not found" });

  // Cancel in Stripe if available
  if (stripe && client.stripe_sub_id) {
    try {
      await stripe.subscriptions.update(client.stripe_sub_id, { cancel_at_period_end: true });
    } catch (e) {
      console.error("Stripe cancellation error:", e.message);
    }
  }

  await supabase.from("clients").update({ subscription_status: "cancelling" }).eq("id", clientId);
  await logAudit(clientId, "cancellation", "subscription_status", client.subscription_status, "cancelling", ip);

  // Send confirmation email
  if (process.env.SENDGRID_KEY && client.email) {
    await sgMail.send({
      to: client.email,
      from: process.env.SENDGRID_FROM || "noreply@bleedleads.com",
      subject: "Your BleedLeads subscription has been cancelled",
      text: `Hi ${client.name},\n\nYour BleedLeads subscription has been cancelled and will remain active until the end of your current billing period.\n\nIf this was a mistake or you change your mind, reply to this email and we will sort it out.\n\nBleedLeads`,
    }).catch(console.error);
  }

  res.json({ ok: true, message: "Subscription cancelled. You will retain access until the end of your billing period." });
});

// ── Win tracking ──────────────────────────────────────────────
app.put("/client/leads/:id/win", authMiddleware, async (req, res) => {
  const clientId = req.user.id;
  const leadId   = req.params.id;
  const { won, jobValue, wonNotes } = req.body;

  // Verify lead belongs to this client
  const { data: lead } = await supabase.from("leads").select("id, client_id").eq("id", leadId).single();
  if (!lead) return res.status(404).json({ error: "Lead not found" });
  if (String(lead.client_id) !== String(clientId)) return res.status(403).json({ error: "Not authorized" });

  const updates = {
    won: won === true,
    won_at: won === true ? new Date().toISOString() : null,
    job_value: won === true && jobValue ? parseFloat(jobValue) : null,
    won_notes: wonNotes || null,
  };

  const { data, error } = await supabase.from("leads").update(updates).eq("id", leadId).select().single();
  if (error) return res.status(400).json({ error: error.message });
  res.json({ ok: true, lead: data });
});

// Admin win update — admin can update any lead
app.put("/admin/leads/:id/win", adminMiddleware, async (req, res) => {
  const leadId = req.params.id;
  const { won, jobValue, wonNotes } = req.body;

  const updates = {
    won: won === true,
    won_at: won === true ? new Date().toISOString() : null,
    job_value: won === true && jobValue ? parseFloat(jobValue) : null,
    won_notes: wonNotes || null,
  };

  const { data, error } = await supabase.from("leads").update(updates).eq("id", leadId).select().single();
  if (error) return res.status(400).json({ error: error.message });
  res.json({ ok: true, lead: data });
});

// ── Revenue stats ─────────────────────────────────────────────
app.get("/client/stats", authMiddleware, async (req, res) => {
  const clientId = req.user.id;
  const now = new Date();
  const monthStart = new Date(now.getFullYear(), now.getMonth(), 1).toISOString();

  const [allWins, monthWins] = await Promise.all([
    supabase.from("leads").select("job_value").eq("client_id", clientId).eq("won", true),
    supabase.from("leads").select("job_value").eq("client_id", clientId).eq("won", true).gte("won_at", monthStart),
  ]);

  const totalRevenue = (allWins.data || []).reduce((sum, l) => sum + (parseFloat(l.job_value) || 0), 0);
  const monthRevenue = (monthWins.data || []).reduce((sum, l) => sum + (parseFloat(l.job_value) || 0), 0);

  res.json({
    jobsWon:      (allWins.data || []).length,
    totalRevenue,
    monthJobs:    (monthWins.data || []).length,
    monthRevenue,
  });
});

// Admin stats — all clients combined
app.get("/admin/stats/revenue", adminMiddleware, async (req, res) => {
  const now = new Date();
  const monthStart = new Date(now.getFullYear(), now.getMonth(), 1).toISOString();

  const [allWins, monthWins] = await Promise.all([
    supabase.from("leads").select("job_value, client_id").eq("won", true),
    supabase.from("leads").select("job_value, client_id").eq("won", true).gte("won_at", monthStart),
  ]);

  const totalRevenue = (allWins.data || []).reduce((sum, l) => sum + (parseFloat(l.job_value) || 0), 0);
  const monthRevenue = (monthWins.data || []).reduce((sum, l) => sum + (parseFloat(l.job_value) || 0), 0);

  res.json({
    jobsWon:      (allWins.data || []).length,
    totalRevenue,
    monthJobs:    (monthWins.data || []).length,
    monthRevenue,
  });
});

// ── Export ────────────────────────────────────────────────────
app.get("/client/export", authMiddleware, async (req, res) => {
  const range = req.query.range || "all";
  let allLeads = await getLeadsForClient(req.user.id, 1000);
  if (range !== "all") {
    const now = new Date();
    let start;
    if (range === "week")  start = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    if (range === "month") start = new Date(now.getFullYear(), now.getMonth(), 1);
    if (range === "year")  start = new Date(now.getFullYear(), 0, 1);
    if (start) allLeads = allLeads.filter(l => new Date(l.created_at) >= start);
  }
  const leads = allLeads;

  const rows = [
    ["Date", "Time", "Name", "Phone", "Source", "Service", "Status", "AI Reply", "Won", "Job Value", "Won At", "Job Notes"],
    ...leads.map(l => [
      new Date(l.created_at).toLocaleDateString("en-US", {month:"2-digit",day:"2-digit",year:"numeric"}),
      new Date(l.created_at).toLocaleTimeString("en-US", {hour:"2-digit",minute:"2-digit",hour12:true}),
      l.name,
      l.phone || "",
      l.source,
      l.service || "",
      l.conversation_status || l.status,
      (l.ai_reply || "").replace(/,/g, ";"),
      l.won ? "Yes" : "No",
      l.job_value ? `$${l.job_value}` : "",
      l.won_at ? new Date(l.won_at).toLocaleDateString("en-US", {month:"2-digit",day:"2-digit",year:"numeric"}) : "",
      l.won_notes || "",
    ]),
  ];

  const csv = rows.map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(",")).join("\n");
  res.setHeader("Content-Type", "text/csv");
  res.setHeader("Content-Disposition", `attachment; filename="bleedleads-export-${new Date().toISOString().slice(0,10)}.csv"`);
  res.send(csv);
});

app.get("/admin/export/:clientId", adminMiddleware, async (req, res) => {
  const range = req.query.range || "all";
  let allLeads = await getLeadsForClient(req.params.clientId, 1000);
  if (range !== "all") {
    const now = new Date();
    let start;
    if (range === "week")  start = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    if (range === "month") start = new Date(now.getFullYear(), now.getMonth(), 1);
    if (range === "year")  start = new Date(now.getFullYear(), 0, 1);
    if (start) allLeads = allLeads.filter(l => new Date(l.created_at) >= start);
  }
  const leads = allLeads;
  const client = await getClientById(req.params.clientId);

  const rows = [
    ["Date", "Time", "Name", "Phone", "Source", "Service", "Status", "AI Reply", "Won", "Job Value", "Won At", "Job Notes"],
    ...leads.map(l => [
      new Date(l.created_at).toLocaleDateString("en-US", {month:"2-digit",day:"2-digit",year:"numeric"}),
      new Date(l.created_at).toLocaleTimeString("en-US", {hour:"2-digit",minute:"2-digit",hour12:true}),
      l.name,
      l.phone || "",
      l.source,
      l.service || "",
      l.conversation_status || l.status,
      (l.ai_reply || "").replace(/,/g, ";"),
      l.won ? "Yes" : "No",
      l.job_value ? `$${l.job_value}` : "",
      l.won_at ? new Date(l.won_at).toLocaleDateString("en-US", {month:"2-digit",day:"2-digit",year:"numeric"}) : "",
      l.won_notes || "",
    ]),
  ];

  const csv = rows.map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(",")).join("\n");
  res.setHeader("Content-Type", "text/csv");
  res.setHeader("Content-Disposition", `attachment; filename="bleedleads-${client?.name || req.params.clientId}-${new Date().toISOString().slice(0,10)}.csv"`);
  res.send(csv);
});

// ── Website Chat Widget ───────────────────────────────────────

// Serve the embeddable widget JavaScript
// Contractors embed: <script src="https://your-railway-url/widget.js?client=CLIENT_ID"></script>
app.get("/widget.js", (req, res) => {
  const clientId = req.query.client;
  if (!clientId) return res.status(400).send("// Missing client ID");

  const apiUrl = "https://leadagent-server-production.up.railway.app";

  const js = `
(function() {
  var BL_CLIENT = "${clientId}";
  var BL_API    = "${apiUrl}";
  var BL_THREAD = "widget-" + BL_CLIENT + "-" + Math.random().toString(36).slice(2);
  var BL_OPEN   = false;

  // ── Styles ──
  var style = document.createElement("style");
  style.textContent = [
    "#bl-btn{position:fixed;bottom:24px;right:24px;width:56px;height:56px;border-radius:50%;background:#D90000;border:none;cursor:pointer;box-shadow:0 4px 16px rgba(217,0,0,0.4);display:flex;align-items:center;justify-content:center;z-index:99999;transition:transform 0.2s;}",
    "#bl-btn:hover{transform:scale(1.08);}",
    "#bl-btn svg{width:24px;height:24px;fill:#fff;}",
    "#bl-box{position:fixed;bottom:92px;right:24px;width:340px;max-width:calc(100vw - 32px);background:#111;border:1px solid #2A2A2A;border-radius:12px;box-shadow:0 8px 32px rgba(0,0,0,0.6);z-index:99998;display:none;flex-direction:column;overflow:hidden;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;}",
    "#bl-head{background:#D90000;padding:14px 18px;display:flex;align-items:center;justify-content:space-between;}",
    "#bl-head-title{color:#fff;font-weight:700;font-size:15px;letter-spacing:0.02em;}",
    "#bl-head-sub{color:rgba(255,255,255,0.7);font-size:11px;margin-top:2px;}",
    "#bl-close{background:none;border:none;color:rgba(255,255,255,0.7);font-size:20px;cursor:pointer;padding:0;line-height:1;}",
    "#bl-msgs{flex:1;overflow-y:auto;padding:16px;max-height:320px;min-height:120px;display:flex;flex-direction:column;gap:10px;}",
    ".bl-msg{max-width:85%;padding:10px 14px;border-radius:12px;font-size:14px;line-height:1.5;}",
    ".bl-msg.bot{background:#1A1A1A;color:#ccc;align-self:flex-start;border-bottom-left-radius:3px;}",
    ".bl-msg.user{background:#D90000;color:#fff;align-self:flex-end;border-bottom-right-radius:3px;}",
    ".bl-typing{display:flex;gap:4px;align-items:center;padding:10px 14px;}",
    ".bl-typing span{width:6px;height:6px;background:#555;border-radius:50%;animation:bl-bounce 1.2s infinite;}",
    ".bl-typing span:nth-child(2){animation-delay:0.2s;}",
    ".bl-typing span:nth-child(3){animation-delay:0.4s;}",
    "@keyframes bl-bounce{0%,60%,100%{transform:translateY(0)}30%{transform:translateY(-6px)}}",
    "#bl-input-row{display:flex;gap:8px;padding:12px 14px;border-top:1px solid #1A1A1A;background:#0D0D0D;}",
    "#bl-input{flex:1;background:#111;border:1px solid #2A2A2A;color:#fff;padding:10px 14px;border-radius:8px;font-size:14px;outline:none;font-family:inherit;}",
    "#bl-input::placeholder{color:#444;}",
    "#bl-input:focus{border-color:#D90000;}",
    "#bl-send{background:#D90000;border:none;color:#fff;padding:10px 16px;border-radius:8px;cursor:pointer;font-size:14px;font-weight:700;white-space:nowrap;}",
    "#bl-send:hover{background:#A30000;}",
    "#bl-send:disabled{background:#333;cursor:not-allowed;}",
  ].join("");
  document.head.appendChild(style);

  // ── Button ──
  var btn = document.createElement("button");
  btn.id = "bl-btn";
  btn.setAttribute("aria-label", "Chat with us");
  btn.innerHTML = '<svg viewBox="0 0 24 24"><path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm-2 12H6v-2h12v2zm0-3H6V9h12v2zm0-3H6V6h12v2z"/></svg>';
  document.body.appendChild(btn);

  // ── Chat box ──
  var box = document.createElement("div");
  box.id = "bl-box";
  box.innerHTML = [
    '<div id="bl-head">',
    '  <div><div id="bl-head-title">Chat with us</div><div id="bl-head-sub">Typically replies instantly</div></div>',
    '  <button id="bl-close" aria-label="Close">&#x2715;</button>',
    '</div>',
    '<div id="bl-msgs"></div>',
    '<div id="bl-input-row">',
    '  <input id="bl-input" placeholder="Type your message..." autocomplete="off" />',
    '  <button id="bl-send">Send</button>',
    '</div>',
  ].join("");
  document.body.appendChild(box);

  var msgs   = document.getElementById("bl-msgs");
  var input  = document.getElementById("bl-input");
  var send   = document.getElementById("bl-send");
  var greeted = false;

  function addMsg(text, type) {
    var m = document.createElement("div");
    m.className = "bl-msg " + type;
    m.textContent = text;
    msgs.appendChild(m);
    msgs.scrollTop = msgs.scrollHeight;
    return m;
  }

  function showTyping() {
    var t = document.createElement("div");
    t.className = "bl-msg bot bl-typing";
    t.innerHTML = "<span></span><span></span><span></span>";
    msgs.appendChild(t);
    msgs.scrollTop = msgs.scrollHeight;
    return t;
  }

  function greet() {
    if (greeted) return;
    greeted = true;
    setTimeout(function() {
      addMsg("Hi there! What can we help you with today?", "bot");
    }, 400);
  }

  async function sendMessage() {
    var text = input.value.trim();
    if (!text) return;
    input.value = "";
    send.disabled = true;
    addMsg(text, "user");
    var typing = showTyping();
    try {
      var res = await fetch(BL_API + "/webhooks/widget", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ clientId: BL_CLIENT, threadId: BL_THREAD, message: text }),
      });
      var data = await res.json();
      typing.remove();
      addMsg(data.reply || "Thanks! We'll be right with you.", "bot");
    } catch(e) {
      typing.remove();
      addMsg("Sorry, something went wrong. Please try again.", "bot");
    }
    send.disabled = false;
    input.focus();
  }

  btn.addEventListener("click", function() {
    BL_OPEN = !BL_OPEN;
    box.style.display = BL_OPEN ? "flex" : "none";
    btn.innerHTML = BL_OPEN
      ? '<svg viewBox="0 0 24 24"><path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/></svg>'
      : '<svg viewBox="0 0 24 24"><path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm-2 12H6v-2h12v2zm0-3H6V9h12v2zm0-3H6V6h12v2z"/></svg>';
    if (BL_OPEN) { greet(); input.focus(); }
  });

  document.getElementById("bl-close").addEventListener("click", function() {
    BL_OPEN = false;
    box.style.display = "none";
    btn.innerHTML = '<svg viewBox="0 0 24 24"><path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm-2 12H6v-2h12v2zm0-3H6V9h12v2zm0-3H6V6h12v2z"/></svg>';
  });

  send.addEventListener("click", sendMessage);
  input.addEventListener("keydown", function(e) { if (e.key === "Enter") sendMessage(); });
})();
`;

  res.setHeader("Content-Type", "application/javascript");
  res.setHeader("Cache-Control", "public, max-age=300");
  res.send(js);
});

// Widget message handler
app.post("/webhooks/widget", async (req, res) => {
  const { clientId, threadId, message } = req.body;
  if (!clientId || !threadId || !message) return res.status(400).json({ error: "Missing fields" });

  try {
    const client = await getClientById(clientId);
    if (!client || !isSubscriptionActive(client)) {
      return res.json({ reply: "Thanks for reaching out! We'll be in touch shortly." });
    }

    // Check if this is a new lead or existing conversation
    const existingLead = await getLeadByThreadId(threadId);

    if (!existingLead) {
      // New widget lead — create it and get first reply
      const lead = await saveLead({
        client_id:            client.id,
        source:               "website",
        name:                 "Website Visitor",
        phone:                null,
        email:                null,
        message:              message,
        service:              detectService(message),
        status:               "processing",
        thread_id:            threadId,
        phone_collected:      false,
        conversation_status:  "active",
        last_message_at:      new Date().toISOString(),
        created_at:           new Date().toISOString(),
      });

      await saveMessage(lead.id, client.id, "website", threadId, "user", message);
      const reply = await generateFirstReply(lead, client);
      await sendPlatformReply("website", threadId, reply, client);
      await saveMessage(lead.id, client.id, "website", threadId, "assistant", reply);
      await updateLead(lead.id, { status: "awaiting_reply", ai_reply: reply });
      await scheduleFollowUps(lead.id, client.id, threadId, "website");

      return res.json({ reply });

    } else {
      // Existing conversation — route to conversation handler
      // Get the reply by temporarily intercepting sendPlatformReply
      let capturedReply = null;
      const origSend = sendPlatformReply;

      // Process the incoming reply
      const phone = extractPhone(message);
      await saveMessage(existingLead.id, client.id, "website", threadId, "user", message);

      if (phone && !existingLead.phone_collected) {
        // Phone collected — complete the conversation
        await cancelFollowUps(existingLead.id);
        const updatedLead = { ...existingLead, phone, phone_collected: true };
        await updateLead(existingLead.id, {
          phone, phone_collected: true, conversation_status: "completed",
          status: "notified", notified_at: new Date().toISOString(),
        });
        const closingMsg = await generateConversationReply(updatedLead, client, [
          { role: "user", content: existingLead.message },
          { role: "assistant", content: "I can help with that — what is the best number to reach you at?" },
          { role: "user", content: message },
        ]);
        await saveMessage(existingLead.id, client.id, "website", threadId, "assistant", closingMsg);
        const alert = await generateClientAlert(updatedLead, client);
        await Promise.all([
          notifyClient(client, alert),
          updateLead(existingLead.id, { ai_reply: closingMsg, urgency: alert.urgency, alert_sms: alert.sms, alert_email_subject: alert.emailSubject, alert_email_body: alert.emailBody }),
        ]);
        capturedReply = closingMsg;
      } else {
        // Continue conversation
        const history = await loadConversationHistory(threadId);
        capturedReply = await generateConversationReply(existingLead, client, history);
        await saveMessage(existingLead.id, client.id, "website", threadId, "assistant", capturedReply);
      }

      return res.json({ reply: capturedReply });
    }
  } catch (err) {
    console.error("[Widget] Error:", err.message);
    return res.json({ reply: "Thanks for reaching out! We'll be in touch shortly." });
  }
});

// ── Test endpoint ─────────────────────────────────────────────
app.post("/test/lead", async (req, res) => {
  if (process.env.NODE_ENV === "production") return res.status(404).end();
  const { client_id, ...leadData } = req.body;
  res.json({ ok: true });
  const client = client_id
    ? await getClientById(client_id)
    : (await supabase.from("clients").select("*").limit(1).single()).data;
  if (!client) return console.warn("No client found for test lead");
  await handleNewLead(leadData, client);
});

app.get("/health", (_, res) => res.json({ status: "ok", ts: new Date().toISOString() }));

// ── Start ─────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`[BleedLeads] Running on port ${PORT}`);
});
