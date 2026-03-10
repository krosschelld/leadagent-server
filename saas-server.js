/**
 * LeadAgent PRO — SaaS Server
 * ─────────────────────────────────────────────────────────────
 * Multi-tenant webhook server. Each inbound Yelp / GMB webhook
 * is matched to the correct client by their account ID, then
 * the full pipeline runs using that client's settings.
 *
 * Required .env vars:
 *   ANTHROPIC_API_KEY, SUPABASE_URL, SUPABASE_SERVICE_KEY,
 *   TWILIO_SID, TWILIO_AUTH, TWILIO_FROM,
 *   SENDGRID_KEY, SENDGRID_FROM,
 *   YELP_WEBHOOK_SECRET, GMB_VERIFICATION_TOKEN,
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
const { pushToCRM } = require("./crm");

// ── Clients ──────────────────────────────────────────────────
const app     = express();
const claude  = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const twilioClient = (process.env.TWILIO_SID && process.env.TWILIO_AUTH) ? twilio(process.env.TWILIO_SID, process.env.TWILIO_AUTH) : null;
const stripe = process.env.STRIPE_SECRET_KEY ? Stripe(process.env.STRIPE_SECRET_KEY) : null;
if (process.env.SENDGRID_KEY) sgMail.setApiKey(process.env.SENDGRID_KEY);

// Raw body needed for Stripe webhook verification
app.use("/webhooks/stripe", express.raw({ type: "application/json" }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ── CORS (allow client dashboards) ───────────────────────────
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
    req.user = jwt.verify(token, process.env.JWT_SECRET || "leadagent-secret");
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
  if (/ac|air.?condition|hvac|cool/i.test(text))      return "AC Repair / HVAC";
  if (/water.?heater|hot.?water/i.test(text))          return "Water Heater";
  if (/leak|pipe|plumb|drain|toilet|faucet/i.test(text)) return "Plumbing";
  if (/electric|outlet|circuit|breaker/i.test(text))  return "Electrical";
  if (/furnace|boiler/i.test(text))                    return "Furnace Repair";
  return "General Home Repair";
}

function verifyYelpSignature(req) {
  const sig = req.headers["x-yelp-signature"] || "";
  const hmac = crypto
    .createHmac("sha256", process.env.YELP_WEBHOOK_SECRET)
    .update(JSON.stringify(req.body))
    .digest("hex");
  return sig === hmac;
}

// ── DB helpers ────────────────────────────────────────────────
async function getClientByYelp(yelpAccountId) {
  const { data } = await supabase
    .from("clients")
    .select("*")
    .eq("yelp_account_id", yelpAccountId)
    .single();
  return data;
}

async function getClientByGMB(gmbAccountId) {
  const { data } = await supabase
    .from("clients")
    .select("*")
    .eq("gmb_account_id", gmbAccountId)
    .single();
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

async function getAllClients() {
  const { data } = await supabase
    .from("clients")
    .select("*, leads(count)")
    .order("created_at", { ascending: false });
  return data || [];
}

async function getLeadsForClient(clientId, limit = 100) {
  const { data } = await supabase
    .from("leads")
    .select("*")
    .eq("client_id", clientId)
    .order("created_at", { ascending: false })
    .limit(limit);
  return data || [];
}

async function getAllLeads(limit = 200) {
  const { data } = await supabase
    .from("leads")
    .select("*, clients(name, email)")
    .order("created_at", { ascending: false })
    .limit(limit);
  return data || [];
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
async function generateReply(lead, client) {
  const msg = await claude.messages.create({
    model: "claude-sonnet-4-20250514",
    max_tokens: 300,
    system: `You are a friendly AI assistant for "${client.ai_persona}", a home services company.
You respond to leads from Yelp and Google My Business.
Write a warm first reply that: acknowledges their issue, confirms you can help, asks ONE qualifying question.
Under 3 sentences. Sound human, never robotic.`,
    messages: [{ role: "user", content: `Lead via ${lead.source}: "${lead.message}"` }],
  });
  return msg.content[0].text;
}

async function generateClientAlert(lead, aiReply, client) {
  const msg = await claude.messages.create({
    model: "claude-sonnet-4-20250514",
    max_tokens: 400,
    system: `Generate a lead alert for a home services business owner. Return ONLY valid JSON, no markdown.
Keys: sms (under 160 chars), emailSubject, emailBody (4-6 lines), urgency ("emergency"|"same-day"|"scheduled").`,
    messages: [{
      role: "user",
      content: `Business: ${client.name}\nLead: ${lead.name} | Phone: ${lead.phone || "TBD"} | Source: ${lead.source} | Service: ${lead.service}\nMessage: "${lead.message}"\nAI replied: "${aiReply}"`,
    }],
  });
  try {
    return JSON.parse(msg.content[0].text.replace(/```json|```/g, "").trim());
  } catch {
    return {
      sms: `🔔 New lead: ${lead.name} | ${lead.phone || "no phone"} | ${lead.service}`,
      emailSubject: `New Lead: ${lead.name} — ${lead.service}`,
      emailBody: `Name: ${lead.name}\nPhone: ${lead.phone || "TBD"}\nService: ${lead.service}\nSource: ${lead.source}\nMessage: ${lead.message}`,
      urgency: "scheduled",
    };
  }
}

// ── Notification helpers ──────────────────────────────────────
async function notifyClient(client, alert) {
  const results = { sms: false, email: false };

  if (twilioClient && client.notify_sms && client.phone) {
    try {
      await twilioClient.messages.create({
        from: process.env.TWILIO_FROM,
        to: client.phone,
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
        to: client.email,
        from: process.env.SENDGRID_FROM || "noreply@leadagentpro.com",
        subject: alert.emailSubject,
        text: alert.emailBody,
      });
      results.email = true;
    } catch (e) {
      console.error(`Email failed for client ${client.id}:`, e.message);
    }
  }

  return results;
}

// ── Core pipeline ─────────────────────────────────────────────
async function handleNewLead(rawLead, client) {
  if (!isSubscriptionActive(client)) {
    console.warn(`[LeadAgent] Client ${client.id} subscription inactive — skipping`);
    return;
  }

  console.log(`[LeadAgent] New lead for client "${client.name}" from ${rawLead.source}: ${rawLead.name}`);

  const lead = await saveLead({
    client_id: client.id,
    source:    rawLead.source,
    name:      rawLead.name,
    phone:     rawLead.phone || null,
    email:     rawLead.email || null,
    message:   rawLead.message,
    service:   detectService(rawLead.message),
    status:    "processing",
    created_at: new Date().toISOString(),
  });

  try {
    const aiReply  = await generateReply(lead, client);
    const alert    = await generateClientAlert(lead, aiReply, client);

    // Push to CRM in parallel with client notification
    const [notified, crmResult] = await Promise.all([
      notifyClient(client, alert),
      pushToCRM(lead, client, aiReply, alert.urgency),
    ]);

    await updateLead(lead.id, {
      status:               "notified",
      ai_reply:             aiReply,
      alert_sms:            alert.sms,
      alert_email_subject:  alert.emailSubject,
      alert_email_body:     alert.emailBody,
      urgency:              alert.urgency,
      notified_at:          new Date().toISOString(),
      crm_pushed:           crmResult.success,
      crm_lead_id:          crmResult.leadId || null,
      crm_error:            crmResult.error || null,
    });

    console.log(`[LeadAgent] Lead ${lead.id} processed ✓ | SMS:${notified.sms} Email:${notified.email} CRM:${crmResult.success ? crmResult.leadId : "failed — " + crmResult.error}`);
  } catch (err) {
    console.error(`[LeadAgent] Pipeline error:`, err);
    await updateLead(lead.id, { status: "error", error_message: err.message });
  }
}

// ── Webhook routes ────────────────────────────────────────────

// Yelp
app.post("/webhooks/yelp", async (req, res) => {
  if (process.env.YELP_WEBHOOK_SECRET && !verifyYelpSignature(req)) {
    return res.status(401).json({ error: "Invalid signature" });
  }
  const { event_type, lead: yelpLead, business_id } = req.body;
  if (event_type !== "lead" || !yelpLead) return res.status(200).json({ ok: true });
  res.status(200).json({ ok: true });

  const client = await getClientByYelp(business_id);
  if (!client) return console.warn(`[Yelp] No client found for business_id: ${business_id}`);
  await handleNewLead({ source: "yelp", name: yelpLead.name, phone: yelpLead.phone, email: yelpLead.email, message: yelpLead.text || yelpLead.message }, client);
});

// GMB verification
app.get("/webhooks/gmb", (req, res) => {
  if (req.query.token === process.env.GMB_VERIFICATION_TOKEN) return res.status(200).send(req.query.token);
  res.status(403).send("Forbidden");
});

// GMB messages
app.post("/webhooks/gmb", async (req, res) => {
  const { message, context } = req.body;
  if (!message?.text) return res.status(200).json({ ok: true });
  res.status(200).json({ ok: true });

  // GMB passes agent name in context.customContext or the agent ID in message.name
  const gmbAccountId = context?.customContext?.agentId || message.name?.split("/")[1];
  const client = gmbAccountId ? await getClientByGMB(gmbAccountId) : null;
  if (!client) return console.warn(`[GMB] No client found for account: ${gmbAccountId}`);
  await handleNewLead({ source: "gmb", name: context?.userInfo?.displayName || "Google User", phone: null, email: null, message: message.text }, client);
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
        stripe_sub_id: sub.id,
        subscribed_at: sub.status === "active" ? new Date().toISOString() : undefined,
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
          to: client.email,
          from: process.env.SENDGRID_FROM || "noreply@leadagentpro.com",
          subject: "Action required: Payment failed for LeadAgent PRO",
          text: `Hi ${client.name},\n\nYour payment failed. Please update your billing details to continue receiving leads.\n\nLeadAgent PRO`,
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

  // Create Stripe customer
  if (process.env.STRIPE_SECRET_KEY) {
    try {
      const customer = await stripe.customers.create({ email, name, metadata: { client_id: client.id } });
      await supabase.from("clients").update({ stripe_customer_id: customer.id }).eq("id", client.id);
    } catch (e) {
      console.error("Stripe customer creation failed:", e.message);
    }
  }

  const token = jwt.sign({ id: client.id, role: "client" }, process.env.JWT_SECRET || "leadagent-secret", { expiresIn: "30d" });
  res.json({ token, client: { id: client.id, name: client.name, email: client.email, subscription_status: client.subscription_status } });
});

// Client login
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;
  const { data: client } = await supabase.from("clients").select("*").eq("email", email).single();
  if (!client || !(await bcrypt.compare(password, client.password_hash || ""))) {
    return res.status(401).json({ error: "Invalid email or password" });
  }
  const token = jwt.sign({ id: client.id, role: "client" }, process.env.JWT_SECRET || "leadagent-secret", { expiresIn: "30d" });
  res.json({ token, client: { id: client.id, name: client.name, email: client.email, subscription_status: client.subscription_status } });
});

// Admin login (env-based, no DB)
app.post("/auth/admin", (req, res) => {
  const { password } = req.body;
  if (password !== process.env.ADMIN_PASSWORD) return res.status(401).json({ error: "Invalid password" });
  const token = jwt.sign({ role: "admin" }, process.env.JWT_SECRET || "leadagent-secret", { expiresIn: "7d" });
  res.json({ token });
});

// ── Admin API routes ──────────────────────────────────────────
app.get("/admin/clients", adminMiddleware, async (req, res) => {
  const clients = await getAllClients();
  res.json(clients);
});

app.post("/admin/clients", adminMiddleware, async (req, res) => {
  const { name, ownerName, email, phone, yelpAccountId, gmbAccountId, subscriptionStatus, aiPersona } = req.body;
  const { data, error } = await supabase.from("clients").insert([{
    name, owner_name: ownerName, email, phone,
    yelp_account_id: yelpAccountId, gmb_account_id: gmbAccountId,
    subscription_status: subscriptionStatus || "active",
    ai_persona: aiPersona || name,
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
  const leads = await getAllLeads();
  res.json(leads);
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
  const leads = await getLeadsForClient(req.user.id);
  res.json(leads);
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

// Create Stripe checkout session for subscription
app.post("/client/subscribe", authMiddleware, async (req, res) => {
  const { plan } = req.body; // 'starter' | 'growth' | 'pro'
  const client = await getClientById(req.user.id);
  const priceMap = {
    starter: process.env.STRIPE_PRICE_STARTER,
    growth:  process.env.STRIPE_PRICE_GROWTH,
    pro:     process.env.STRIPE_PRICE_PRO,
  };
  const session = await stripe.checkout.sessions.create({
    customer: client.stripe_customer_id,
    mode: "subscription",
    payment_method_types: ["card"],
    line_items: [{ price: priceMap[plan], quantity: 1 }],
    success_url: `${process.env.APP_URL}/dashboard?subscribed=true`,
    cancel_url:  `${process.env.APP_URL}/dashboard?cancelled=true`,
  });
  res.json({ url: session.url });
});

// ── Test endpoint ─────────────────────────────────────────────
app.post("/test/lead", async (req, res) => {
  if (process.env.NODE_ENV === "production") return res.status(404).end();
  const { client_id, ...leadData } = req.body;
  res.json({ ok: true });
  const client = client_id ? await getClientById(client_id) : (await supabase.from("clients").select("*").limit(1).single()).data;
  if (!client) return console.warn("No client found for test lead");
  await handleNewLead(leadData, client);
});

app.get("/health", (_, res) => res.json({ status: "ok", ts: new Date().toISOString() }));

// ── Start ─────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`[LeadAgent SaaS] Running on port ${PORT}`);
});
