const express = require("express");
const nodemailer = require("nodemailer");
const { simpleParser } = require("mailparser");
const net = require("net");
const tls = require("tls");

const app = express();
app.use(express.json({ limit: "10mb" }));

const PORT = process.env.PORT || 3000;
const RELAY_API_KEY = process.env.RELAY_API_KEY;

// Auth middleware — every request must carry the shared bearer token
app.use((req, res, next) => {
  if (!RELAY_API_KEY) {
    return res.status(500).json({ error: "RELAY_API_KEY env var is not set on the relay server." });
  }
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token || token !== RELAY_API_KEY) {
    return res.status(401).json({ error: "Unauthorized — invalid or missing API key." });
  }
  next();
});

// Health check (also requires auth so the endpoint isn't publicly discoverable)
app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

// Verify SMTP credentials without sending a message.
// Body: smtp_host, smtp_port, smtp_username, smtp_password
app.post("/verify", async (req, res) => {
  const { smtp_host, smtp_port, smtp_username, smtp_password } = req.body || {};

  const missing = [];
  if (!smtp_host) missing.push("smtp_host");
  if (!smtp_port) missing.push("smtp_port");
  if (!smtp_username) missing.push("smtp_username");
  if (!smtp_password) missing.push("smtp_password");
  if (missing.length) {
    return res.status(400).json({ error: "Missing required fields: " + missing.join(", ") });
  }

  const transporter = nodemailer.createTransport({
    host: smtp_host,
    port: Number(smtp_port),
    secure: Number(smtp_port) === 465,
    auth: { user: smtp_username, pass: smtp_password },
    connectionTimeout: 15000,
    greetingTimeout: 15000,
    socketTimeout: 15000,
  });

  try {
    await transporter.verify();
    await transporter.close();
    return res.json({ success: true, message: "Connection verified successfully" });
  } catch (err) {
    return res.status(502).json({
      success: false,
      error: err.message,
      code: err.code || null,
    });
  }
});

// Send an email using SMTP credentials supplied in the request body.
// Body:
//   smtp_host, smtp_port, smtp_username, smtp_password,
//   from_email, from_name,
//   to, subject, html, text (optional)
app.post("/send-email", async (req, res) => {
  const {
    smtp_host,
    smtp_port,
    smtp_username,
    smtp_password,
    from_email,
    from_name,
    to,
    subject,
    html,
    text,
    reply_to,
    unsubscribe_url,
    unsubscribe_mailto,
  } = req.body || {};

  // Deliverability best practices: always include a plain-text alternative
  // (Gmail/Yahoo penalize HTML-only bulk mail) and a List-Unsubscribe header
  // (required for bulk senders since Feb 2024).
  function htmlToPlainText(htmlStr) {
    if (!htmlStr) return "";
    return htmlStr
      .replace(/<style[\s\S]*?<\/style>/gi, " ")
      .replace(/<script[\s\S]*?<\/script>/gi, " ")
      .replace(/<br\s*\/?>/gi, "\n")
      .replace(/<\/p>/gi, "\n\n")
      .replace(/<[^>]+>/g, " ")
      .replace(/&nbsp;/g, " ")
      .replace(/&amp;/g, "&")
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">")
      .replace(/[ \t]+/g, " ")
      .replace(/\n{3,}/g, "\n\n")
      .trim();
  }

  const plainText = text || htmlToPlainText(html);
  const unsubMailto = unsubscribe_mailto || `mailto:${from_email}?subject=unsubscribe`;
  const listUnsubscribeValue = unsubscribe_url ? `<${unsubscribe_url}>, <${unsubMailto}>` : `<${unsubMailto}>`;

  // Validate required fields
  const missing = [];
  if (!smtp_host) missing.push("smtp_host");
  if (!smtp_port) missing.push("smtp_port");
  if (!smtp_username) missing.push("smtp_username");
  if (!smtp_password) missing.push("smtp_password");
  if (!from_email) missing.push("from_email");
  if (!to) missing.push("to");
  if (!subject) missing.push("subject");
  if (!html && !text) missing.push("html or text");
  if (missing.length) {
    return res.status(400).json({ error: "Missing required fields: " + missing.join(", ") });
  }

  const transporter = nodemailer.createTransport({
    host: smtp_host,
    port: Number(smtp_port),
    secure: Number(smtp_port) === 465, // true for 465, false (STARTTLS) for 587/25
    auth: { user: smtp_username, pass: smtp_password },
    connectionTimeout: 15000,
    greetingTimeout: 15000,
    socketTimeout: 20000,
  });

  try {
    const info = await transporter.sendMail({
      from: from_name ? `"${from_name}" <${from_email}>` : from_email,
      to,
      subject,
      html,
      text: plainText,
      replyTo: reply_to || from_email,
      headers: {
        "List-Unsubscribe": listUnsubscribeValue,
        "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
      },
    });
    return res.json({ success: true, messageId: info.messageId, response: info.response });
  } catch (err) {
    return res.status(502).json({
      success: false,
      error: err.message,
      code: err.code || null,
    });
  }
});

// Fetch emails from IMAP mailbox
// Body: imapHost, imapPort, imapUser, imapPass, mailbox, since (ISO), limit
app.post("/fetch-inbox", async (req, res) => {
  const { imapHost, imapPort, imapUser, imapPass, mailbox, since, limit } = req.body || {};

  const missing = [];
  if (!imapHost) missing.push("imapHost");
  if (!imapPort) missing.push("imapPort");
  if (!imapUser) missing.push("imapUser");
  if (!imapPass) missing.push("imapPass");
  if (missing.length) {
    return res.status(400).json({ error: "Missing required fields: " + missing.join(", ") });
  }

  try {
    const emails = await fetchEmailsFromImap({
      host: imapHost,
      port: Number(imapPort),
      user: imapUser,
      pass: imapPass,
      mailbox: mailbox || "INBOX",
      since: since ? new Date(since) : new Date(Date.now() - 7 * 24 * 60 * 60 * 1000),
      limit: Number(limit) || 50,
    });

    return res.json({ success: true, emails });
  } catch (err) {
    return res.status(502).json({
      success: false,
      error: err.message,
    });
  }
});

async function fetchEmailsFromImap({ host, port, user, pass, mailbox, since, limit }) {
  const socket = tls.connect({ host, port, rejectUnauthorized: false }, () => {
    console.log("IMAP connected");
  });

  return new Promise((resolve, reject) => {
    let buffer = "";
    let tagNum = 0;
    const emails = [];
    let uids = [];

    const tag = () => `A${++tagNum}`;

    const sendCmd = (cmd) => {
      const t = tag();
      socket.write(`${t} ${cmd}\r\n`);
      return new Promise((res) => {
        const handler = (data) => {
          buffer += data.toString();
          if (buffer.includes(`${t} `)) {
            socket.removeListener("data", handler);
            const response = buffer;
            buffer = "";
            res(response);
          }
        };
        socket.on("data", handler);
      });
    };

    socket.on("connect", async () => {
      try {
        // Read greeting
        buffer = "";
        await new Promise((res) => {
          const handler = () => res();
          socket.once("data", handler);
        });
        buffer = "";

        // Login
        await sendCmd(`LOGIN "${user}" "${pass}"`);

        // Select mailbox
        await sendCmd(`SELECT ${mailbox}`);

        // Search for emails since date
        const sinceStr = formatImapDate(since);
        const searchRes = await sendCmd(`SEARCH SINCE ${sinceStr}`);
        const match = searchRes.match(/\* SEARCH(.*?)(?:\r\n|$)/);
        const uidStr = match ? match[1].trim() : "";
        uids = uidStr.split(/\s+/).filter(Boolean).slice(-limit);

        // Fetch email details
        for (const uid of uids) {
          try {
            const fetchRes = await sendCmd(`FETCH ${uid} (RFC822)`);
            const rfc822Match = fetchRes.match(/RFC822\s*\{(\d+)\}\r\n([\s\S]*?)\r\n\)/);
            if (rfc822Match) {
              const emailBody = rfc822Match[2];
              const parsed = await parseEmail(emailBody);
              emails.push(parsed);
            }
          } catch (e) {
            console.error(`Error fetching UID ${uid}:`, e.message);
          }
        }

        // Logout
        await sendCmd("LOGOUT");
        socket.end();
        resolve(emails);
      } catch (err) {
        socket.end();
        reject(err);
      }
    });

    socket.on("error", (err) => {
      reject(err);
    });
  });
}

function formatImapDate(date) {
  const d = new Date(date);
  const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const day = String(d.getUTCDate()).padStart(2, "0");
  const month = months[d.getUTCMonth()];
  const year = d.getUTCFullYear();
  return `${day}-${month}-${year}`;
}

async function parseEmail(emailBody) {
  return new Promise((resolve) => {
    simpleParser(emailBody, async (err, parsed) => {
      if (err) {
        return resolve({
          from: "unknown",
          to: "unknown",
          subject: "unknown",
          text: "",
          html: "",
          date: new Date().toISOString(),
          messageId: "",
          inReplyTo: "",
          references: "",
        });
      }

      const from = parsed.from?.text || parsed.from?.email || "unknown";
      const to = parsed.to?.text || parsed.to?.email || "unknown";
      const subject = parsed.subject || "(no subject)";
      const text = parsed.text || "";
      const html = parsed.html || "";
      const date = (parsed.date || new Date()).toISOString();
      const messageId = parsed.messageId || "";
      const inReplyTo = parsed.inReplyTo || "";
      const references = Array.isArray(parsed.references) ? parsed.references.join(", ") : (parsed.references || "");

      resolve({
        from,
        to,
        subject,
        text,
        html,
        date,
        messageId,
        inReplyTo,
        references,
      });
    });
  });
}

app.listen(PORT, () => {
  console.log(`SMTP relay listening on port ${PORT}`);
});
