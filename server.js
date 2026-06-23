const express = require("express");
const nodemailer = require("nodemailer");

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
  } = req.body || {};

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
      text,
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

app.listen(PORT, () => {
  console.log(`SMTP relay listening on port ${PORT}`);
});
