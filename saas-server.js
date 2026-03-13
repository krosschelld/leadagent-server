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
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ── CORS ─────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  if (req.method === "OPTIONS") return res.sendStatus(200);
  next();
});

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
    model: "claude-sonnet-4-20250514",
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
  const messages = history.map(h => ({ role: h.role, content: h.message }));

  const msg = await claude.messages.create({
    model: "claude-sonnet-4-20250514",
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
    model: "claude-sonnet-4-20250514",
    max_tokens: 100,
    system: systemPrompt,
    messages: [{ role: "user", content: attemptContext[attemptNumber] }],
  });
  return msg.content[0].text;
}

// Generate the contractor alert when a phone number is finally collected
async function generateClientAlert(lead, client) {
  const msg = await claude.messages.create({
    model: "claude-sonnet-4-20250514",
    max_tokens: 400,
    system: `Generate a lead alert for a home services business owner. Return ONLY valid JSON, no markdown.
Keys: sms (under 160 chars), emailSubject, emailBody (4-6 lines), urgency ("emergency"|"same-day"|"scheduled").
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
      urgency: "scheduled",
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

  if (platform === "email") {
    // One-shot email reply for Angi / Thumbtack inbound email leads
    if (client.email && process.env.SENDGRID_KEY) {
      await sgMail.send({
        to: threadId,  // threadId is the customer's email address for email leads
        from: process.env.SENDGRID_FROM,
        subject: `Re: Your ${client.name} inquiry`,
        text: message,
      }).catch(e => console.error("Email reply failed:", e.message));
    }
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

// Inbound email (Angi / Thumbtack via SendGrid Inbound Parse)
// SendGrid posts form data to this endpoint when an email arrives at leads@bleedleads.com
app.post("/webhooks/email", async (req, res) => {
  res.status(200).json({ ok: true });
  const { from, subject, text, to } = req.body;
  if (!text) return;

  // The 'to' address will be leads+{clientId}@bleedleads.com — extract client ID
  const clientIdMatch = (to || "").match(/leads\+(\d+)@/);
  if (!clientIdMatch) { console.warn("[Email] Could not extract client ID from to address:", to); return; }

  const client = await getClientById(clientIdMatch[1]);
  if (!client) { console.warn("[Email] No client found for ID:", clientIdMatch[1]); return; }

  // Detect source from subject line
  const source = /angi/i.test(subject) ? "angi" : /thumbtack/i.test(subject) ? "thumbtack" : "email";

  // Use sender email as thread ID so replies route back correctly
  const senderEmail = (from || "").match(/<(.+)>/)?.[1] || from;

  await handleNewLead({
    source,
    name:      from,
    phone:     extractPhone(text) || null,
    email:     senderEmail,
    message:   text.substring(0, 1000),
    thread_id: senderEmail,
  }, client);
});

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
app.post("/auth/signup", async (req, res) => {
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
  res.json({ token, client: { id: client.id, name: client.name, email: client.email, subscription_status: client.subscription_status } });
});

// Client login
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;
  const { data: client } = await supabase.from("clients").select("*").eq("email", email).single();
  if (!client || !(await bcrypt.compare(password, client.password_hash || ""))) {
    return res.status(401).json({ error: "Invalid email or password" });
  }
  const token = jwt.sign({ id: client.id, role: "client" }, process.env.JWT_SECRET || "bleedleads-secret", { expiresIn: "30d" });
  res.json({ token, client: { id: client.id, name: client.name, email: client.email, subscription_status: client.subscription_status } });
});

// Admin login
app.post("/auth/admin", (req, res) => {
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
