/**
 * BleedLeads — CRM Integration Module
 * ─────────────────────────────────────────────────────────────
 * Dynamically routes each lead to the correct CRM based on
 * the client's crm_type setting. Each handler is self-contained
 * and returns { success, leadId, error }.
 *
 * Supported CRMs:
 *   - GoHighLevel  (most popular for home service agencies)
 *   - HubSpot      (free tier, widely used)
 *   - Jobber       (built for home services)
 *   - ServiceTitan (enterprise home services)
 *   - Webhook      (generic — works with Zapier, Make, any CRM)
 */

// ── Urgency mapping ───────────────────────────────────────────
const URGENCY_PRIORITY = { emergency: "HIGH", "same-day": "MEDIUM", scheduled: "LOW" };

// ── Main dispatcher ───────────────────────────────────────────

/**
 * Push a lead to the client's configured CRM.
 * Called from the main pipeline after AI reply is generated.
 *
 * @param {Object} lead    - Full lead object from DB
 * @param {Object} client  - Full client object from DB
 * @param {string} aiReply - The AI-generated reply text
 * @param {string} urgency - "emergency" | "same-day" | "scheduled"
 * @returns {{ success: boolean, leadId: string|null, error: string|null }}
 */
async function pushToCRM(lead, client, aiReply, urgency) {
  if (!client.crm_type || client.crm_type === "none") {
    return { success: false, leadId: null, error: "No CRM configured" };
  }

  const handlers = {
    gohighlevel:  pushToGoHighLevel,
    hubspot:      pushToHubSpot,
    jobber:       pushToJobber,
    servicetitan: pushToServiceTitan,
    webhook:      pushToWebhook,
  };

  const handler = handlers[client.crm_type];
  if (!handler) return { success: false, leadId: null, error: `Unknown CRM type: ${client.crm_type}` };

  try {
    console.log(`[CRM] Pushing lead ${lead.id} to ${client.crm_type} for client ${client.name}`);
    const result = await handler(lead, client, aiReply, urgency);
    console.log(`[CRM] ✓ Lead ${lead.id} pushed to ${client.crm_type} — CRM ID: ${result.leadId}`);
    return result;
  } catch (err) {
    console.error(`[CRM] ✗ Failed to push lead ${lead.id} to ${client.crm_type}:`, err.message);
    return { success: false, leadId: null, error: err.message };
  }
}

// ── GoHighLevel ───────────────────────────────────────────────
// Docs: https://highlevel.stoplight.io/docs/integrations
// Creates a Contact + Opportunity in the client's pipeline.

async function pushToGoHighLevel(lead, client, aiReply, urgency) {
  const headers = {
    "Authorization": `Bearer ${client.crm_api_key}`,
    "Content-Type": "application/json",
    "Version": "2021-07-28",
  };

  // 1 — Create or update contact
  const contactPayload = {
    locationId:  client.crm_location_id,
    firstName:   lead.name.split(" ")[0],
    lastName:    lead.name.split(" ").slice(1).join(" ") || "",
    phone:       lead.phone || undefined,
    email:       lead.email || undefined,
    source:      lead.source === "yelp" ? "Yelp" : "Google My Business",
    tags:        [lead.service, lead.source, urgency, "leadagent-pro"],
    customFields: [
      { key: "lead_message",   fieldValue: lead.message },
      { key: "ai_reply_sent",  fieldValue: aiReply },
      { key: "lead_source",    fieldValue: lead.source },
      { key: "service_needed", fieldValue: lead.service },
    ],
  };

  const contactRes = await fetch("https://services.leadconnectorhq.com/contacts/", {
    method: "POST", headers, body: JSON.stringify(contactPayload),
  });
  const contactData = await contactRes.json();
  if (!contactRes.ok) throw new Error(`GHL contact error: ${JSON.stringify(contactData)}`);
  const contactId = contactData.contact?.id;

  // 2 — Create opportunity in pipeline (if pipeline configured)
  if (client.crm_pipeline_id && contactId) {
    const oppPayload = {
      pipelineId:   client.crm_pipeline_id,
      locationId:   client.crm_location_id,
      name:         `${lead.name} — ${lead.service}`,
      pipelineStageId: client.crm_stage_id || undefined,
      status:       "open",
      contactId,
      monetaryValue: 0,
      source:       lead.source === "yelp" ? "Yelp" : "Google My Business",
      assignedTo:   undefined,
      customFields: contactPayload.customFields,
    };
    await fetch("https://services.leadconnectorhq.com/opportunities/", {
      method: "POST", headers, body: JSON.stringify(oppPayload),
    });
  }

  return { success: true, leadId: contactId, error: null };
}

// ── HubSpot ───────────────────────────────────────────────────
// Docs: https://developers.hubspot.com/docs/api/crm/contacts
// Creates a Contact + Deal.

async function pushToHubSpot(lead, client, aiReply, urgency) {
  const headers = {
    "Authorization": `Bearer ${client.crm_api_key}`,
    "Content-Type": "application/json",
  };

  // 1 — Create contact
  const [firstName, ...lastParts] = lead.name.split(" ");
  const contactPayload = {
    properties: {
      firstname:        firstName,
      lastname:         lastParts.join(" ") || "",
      phone:            lead.phone || "",
      email:            lead.email || "",
      hs_lead_status:   "NEW",
      lead_source:      lead.source === "yelp" ? "YELP" : "GOOGLE_MY_BUSINESS",
      service_needed:   lead.service,
      original_message: lead.message,
      ai_reply_sent:    aiReply,
      priority:         URGENCY_PRIORITY[urgency] || "LOW",
    },
  };

  const contactRes = await fetch("https://api.hubapi.com/crm/v3/objects/contacts", {
    method: "POST", headers, body: JSON.stringify(contactPayload),
  });
  const contactData = await contactRes.json();
  if (!contactRes.ok) throw new Error(`HubSpot contact error: ${JSON.stringify(contactData)}`);
  const contactId = contactData.id;

  // 2 — Create deal
  const dealPayload = {
    properties: {
      dealname:    `${lead.name} — ${lead.service}`,
      dealstage:   client.crm_stage_id || "appointmentscheduled",
      pipeline:    client.crm_pipeline_id || "default",
      lead_source: lead.source === "yelp" ? "Yelp" : "Google My Business",
      priority:    URGENCY_PRIORITY[urgency] || "LOW",
    },
    associations: [{
      to: { id: contactId },
      types: [{ associationCategory: "HUBSPOT_DEFINED", associationTypeId: 3 }],
    }],
  };

  const dealRes = await fetch("https://api.hubapi.com/crm/v3/objects/deals", {
    method: "POST", headers, body: JSON.stringify(dealPayload),
  });
  const dealData = await dealRes.json();
  if (!dealRes.ok) throw new Error(`HubSpot deal error: ${JSON.stringify(dealData)}`);

  return { success: true, leadId: contactId, error: null };
}

// ── Jobber ────────────────────────────────────────────────────
// Docs: https://developer.getjobber.com/docs
// Uses GraphQL API. Creates a Client + Request.

async function pushToJobber(lead, client, aiReply, urgency) {
  const headers = {
    "Authorization": `Bearer ${client.crm_api_key}`,
    "Content-Type": "application/json",
    "X-JOBBER-GRAPHQL-VERSION": "2024-07-05",
  };

  // Create client record
  const mutation = `
    mutation CreateClient($input: ClientCreateInput!) {
      clientCreate(input: $input) {
        client { id name }
        userErrors { message path }
      }
    }
  `;

  const [firstName, ...lastParts] = lead.name.split(" ");
  const variables = {
    input: {
      firstName,
      lastName: lastParts.join(" ") || "",
      phones: lead.phone ? [{ number: lead.phone, primary: true }] : [],
      emails: lead.email ? [{ address: lead.email, primary: true }] : [],
      notes: `Source: ${lead.source === "yelp" ? "Yelp" : "Google My Business"}\nService: ${lead.service}\nMessage: ${lead.message}\nAI Reply: ${aiReply}\nUrgency: ${urgency}`,
    },
  };

  const res = await fetch("https://api.getjobber.com/api/graphql", {
    method: "POST", headers,
    body: JSON.stringify({ query: mutation, variables }),
  });
  const data = await res.json();
  if (data.errors) throw new Error(`Jobber error: ${JSON.stringify(data.errors)}`);
  if (data.data?.clientCreate?.userErrors?.length) {
    throw new Error(`Jobber userError: ${data.data.clientCreate.userErrors[0].message}`);
  }

  const clientId = data.data?.clientCreate?.client?.id;
  return { success: true, leadId: clientId, error: null };
}

// ── ServiceTitan ──────────────────────────────────────────────
// Docs: https://developer.servicetitan.io
// Creates a Customer + Booking.

async function pushToServiceTitan(lead, client, aiReply, urgency) {
  // ServiceTitan requires a tenant ID embedded in the API key field
  // Format crm_api_key as: "tenantId:clientId:clientSecret"
  const [tenantId, clientId, clientSecret] = (client.crm_api_key || "").split(":");
  if (!tenantId || !clientId || !clientSecret) {
    throw new Error("ServiceTitan crm_api_key must be formatted as tenantId:clientId:clientSecret");
  }

  // Get access token
  const tokenRes = await fetch("https://auth.servicetitan.io/connect/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "client_credentials",
      client_id: clientId,
      client_secret: clientSecret,
    }),
  });
  const tokenData = await tokenRes.json();
  if (!tokenRes.ok) throw new Error(`ServiceTitan auth error: ${tokenData.error}`);

  const headers = {
    "Authorization": `Bearer ${tokenData.access_token}`,
    "Content-Type": "application/json",
    "ST-App-Key": process.env.SERVICETITAN_APP_KEY || client.crm_location_id,
  };

  const baseUrl = `https://api.servicetitan.io/crm/v2/tenant/${tenantId}`;

  // Create customer
  const [firstName, ...lastParts] = lead.name.split(" ");
  const customerPayload = {
    name: lead.name,
    type: "Residential",
    contacts: [
      ...(lead.phone ? [{ type: "Phone", value: lead.phone, memo: "From BleedLeads" }] : []),
      ...(lead.email ? [{ type: "Email", value: lead.email }] : []),
    ],
    leadSource: lead.source === "yelp" ? "Yelp" : "Google My Business",
    customFields: [
      { name: "Service Needed", value: lead.service },
      { name: "Original Message", value: lead.message },
      { name: "AI Reply Sent", value: aiReply },
      { name: "Urgency", value: urgency },
    ],
  };

  const customerRes = await fetch(`${baseUrl}/customers`, {
    method: "POST", headers, body: JSON.stringify(customerPayload),
  });
  const customerData = await customerRes.json();
  if (!customerRes.ok) throw new Error(`ServiceTitan customer error: ${JSON.stringify(customerData)}`);

  return { success: true, leadId: String(customerData.id), error: null };
}

// ── Generic Webhook ───────────────────────────────────────────
// Works with Zapier, Make (Integromat), n8n, or any custom webhook.
// Client sets crm_webhook_url to their Zapier/Make webhook URL.

async function pushToWebhook(lead, client, aiReply, urgency) {
  if (!client.crm_webhook_url) throw new Error("No webhook URL configured");

  const payload = {
    // Standard lead fields
    lead_id:        lead.id,
    name:           lead.name,
    phone:          lead.phone,
    email:          lead.email,
    message:        lead.message,
    service:        lead.service,
    source:         lead.source,
    urgency,
    ai_reply:       aiReply,
    created_at:     lead.created_at,

    // Client info
    business_name:  client.name,
    client_id:      client.id,

    // Metadata
    sent_by:        "BleedLeads",
    sent_at:        new Date().toISOString(),
  };

  const res = await fetch(client.crm_webhook_url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Webhook returned ${res.status}: ${text}`);
  }

  // Try to extract an ID from the response if available
  let leadId = null;
  try {
    const data = await res.json();
    leadId = data.id || data.leadId || data.contact_id || null;
  } catch {}

  return { success: true, leadId, error: null };
}

module.exports = { pushToCRM };
