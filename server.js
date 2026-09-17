const express = require("express");
const dns = require("node:dns").promises;
const net = require("node:net");
const path = require("node:path");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: "2mb" }));
app.use(express.static(path.join(__dirname, "public")));

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const DOMAIN_RE = /^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/;

const PROVIDERS = [
  { name: "Google Workspace / Gmail", patterns: ["google.com", "googlemail.com", "aspmx.l.google.com", "gmail-smtp-in.l.google.com"] },
  { name: "Microsoft 365 / Outlook", patterns: ["protection.outlook.com", "outlook.com", "microsoft.com"] },
  { name: "Yahoo Mail", patterns: ["yahoodns.net", "yahoo.com"] },
  { name: "Zoho Mail", patterns: ["zoho.com", "zoho.eu", "zohomail.com"] },
  { name: "Hostinger", patterns: ["hostinger.com", "hostinger.ph", "dhosting.com"] },
  { name: "GoDaddy / secureserver", patterns: ["secureserver.net", "mail.godaddy.com"] },
  { name: "Cloudflare Email Routing", patterns: ["cloudflare.net"] }
];

function cleanInput(value) {
  let s = String(value ?? "").trim();
  if (!s) return "";

  // Markdown link: [label](target)
  const md = s.match(/^\[([^\]]+)\]\(([^)]+)\)$/);
  if (md) s = md[2];

  s = s.replace(/^mailto:/i, "");
  s = s.replace(/^https?:\/\//i, "");
  s = s.split(/[/?#]/)[0];
  s = s.trim().replace(/[<>"'`]/g, "");

  // If a pasted line contains surrounding text, extract the first email.
  const emailMatch = s.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}/i);
  if (emailMatch) return emailMatch[0].toLowerCase();

  return s.toLowerCase();
}

function classify(value) {
  const input = cleanInput(value);
  if (EMAIL_RE.test(input)) {
    return { input, type: "EMAIL", domain: input.split("@")[1] };
  }
  if (DOMAIN_RE.test(input)) {
    return { input, type: "DOMAIN", domain: input };
  }
  return { input, type: "INVALID", domain: "" };
}

function providerFor(mxHosts) {
  const joined = mxHosts.join(" ").toLowerCase();
  for (const p of PROVIDERS) {
    if (p.patterns.some(pattern => joined.includes(pattern))) return p.name;
  }
  return "Other / custom mail server";
}

async function resolveMx(domain) {
  try {
    const records = await dns.resolveMx(domain);
    records.sort((a, b) => a.priority - b.priority);
    return {
      ok: records.length > 0,
      records,
      hosts: records.map(r => r.exchange),
      message: records.length ? "MX records found" : "No MX records"
    };
  } catch (err) {
    return { ok: false, records: [], hosts: [], message: err.code || err.message };
  }
}

function smtpCommand(socket, command, timeoutMs = 8000) {
  return new Promise((resolve, reject) => {
    let buffer = "";
    let timer;

    const cleanup = () => {
      clearTimeout(timer);
      socket.removeListener("data", onData);
      socket.removeListener("error", onError);
      socket.removeListener("close", onClose);
      socket.removeListener("timeout", onTimeout);
    };

    const finish = (value, isError = false) => {
      cleanup();
      isError ? reject(value) : resolve(value);
    };

    const onData = chunk => {
      buffer += chunk.toString("utf8");
      const lines = buffer.split(/\r?\n/);

      // Keep incomplete last line.
      buffer = lines.pop() || "";

      for (const line of lines) {
        // SMTP multiline replies continue while the 4th character is '-'.
        if (/^\d{3} /.test(line)) {
          finish(line);
          return;
        }
      }
    };

    const onError = err => finish(err, true);
    const onClose = () => finish(new Error("Connection closed before SMTP response"), true);
    const onTimeout = () => finish(new Error("SMTP timeout"), true);

    socket.on("data", onData);
    socket.once("error", onError);
    socket.once("close", onClose);
    socket.once("timeout", onTimeout);

    timer = setTimeout(() => finish(new Error("SMTP timeout")), timeoutMs);
    socket.write(command + "\r\n");
  });
}

async function smtpVerify(mailHost, email, options = {}) {
  const timeoutMs = options.timeoutMs || 7000;
  const port = options.port || 25;

  return new Promise((resolve) => {
    const socket = net.createConnection({ host: mailHost, port });
    let closed = false;

    const finish = (result) => {
      if (closed) return;
      closed = true;
      try { socket.destroy(); } catch {}
      resolve(result);
    };

    socket.setTimeout(timeoutMs);

    socket.once("error", err => {
      finish({
        status: "NOT_VERIFIABLE",
        code: "CONNECTION_ERROR",
        message: err.code ? `SMTP connection error: ${err.code}` : err.message
      });
    });

    socket.once("timeout", () => {
      finish({
        status: "NOT_VERIFIABLE",
        code: "TIMEOUT",
        message: "SMTP server did not respond before the timeout"
      });
    });

    (async () => {
      try {
        let reply = await waitForReply(socket, timeoutMs);
        if (!is2xxOr3xx(reply)) {
          return finish({ status: "NOT_VERIFIABLE", code: reply.slice(0, 3), message: `SMTP greeting: ${reply}` });
        }

        reply = await sendAndWait(socket, `EHLO email-checker.local`, timeoutMs);
        if (!is2xxOr3xx(reply)) {
          return finish({ status: "NOT_VERIFIABLE", code: reply.slice(0, 3), message: `EHLO rejected: ${reply}` });
        }

        reply = await sendAndWait(socket, `MAIL FROM:<postmaster@email-checker.local>`, timeoutMs);
        if (!is2xxOr3xx(reply)) {
          return finish({ status: "NOT_VERIFIABLE", code: reply.slice(0, 3), message: `MAIL FROM rejected: ${reply}` });
        }

        reply = await sendAndWait(socket, `RCPT TO:<${email}>`, timeoutMs);
        const code = Number(reply.slice(0, 3));

        if (code >= 200 && code < 300) {
          return finish({
            status: "DELIVERABLE",
            code: String(code),
            message: "SMTP server accepted the recipient address"
          });
        }

        if (code >= 500 && code < 600) {
          return finish({
            status: "NOT_DELIVERABLE",
            code: String(code),
            message: `SMTP server rejected the recipient: ${reply}`
          });
        }

        return finish({
          status: "NOT_VERIFIABLE",
          code: String(code),
          message: `SMTP server returned a temporary/ambiguous response: ${reply}`
        });
      } catch (err) {
        finish({
          status: "NOT_VERIFIABLE",
          code: err.code || "SMTP_ERROR",
          message: err.message || "SMTP verification failed"
        });
      }
    })();
  });
}

function is2xxOr3xx(reply) {
  const code = Number(reply.slice(0, 3));
  return code >= 200 && code < 400;
}

function waitForReply(socket, timeoutMs) {
  return new Promise((resolve, reject) => {
    let buffer = "";
    let timer;

    const cleanup = () => {
      clearTimeout(timer);
      socket.removeListener("data", onData);
      socket.removeListener("error", onError);
      socket.removeListener("close", onClose);
    };

    const onData = chunk => {
      buffer += chunk.toString("utf8");
      const lines = buffer.split(/\r?\n/);
      buffer = lines.pop() || "";

      // Find the final SMTP line (e.g. "250 OK"). For multiline replies,
      // the final line uses a space after the status code.
      for (const line of lines) {
        if (/^\d{3} /.test(line)) {
          cleanup();
          resolve(line);
          return;
        }
      }
    };

    const onError = err => {
      cleanup();
      reject(err);
    };

    const onClose = () => {
      cleanup();
      reject(new Error("Connection closed before SMTP response"));
    };

    socket.on("data", onData);
    socket.once("error", onError);
    socket.once("close", onClose);

    timer = setTimeout(() => {
      cleanup();
      reject(new Error("SMTP timeout"));
    }, timeoutMs);
  });
}

function sendAndWait(socket, command, timeoutMs) {
  socket.write(command + "\r\n");
  return waitForReply(socket, timeoutMs);
}

async function checkOne(raw, options = {}) {
  const item = classify(raw);

  if (item.type === "INVALID") {
    return {
      input: item.input || String(raw ?? "").trim(),
      type: "INVALID",
      domain: "",
      mx: "NO",
      mailHost: "",
      provider: "",
      status: "INVALID",
      message: "Not a valid email address or domain"
    };
  }

  const mx = await resolveMx(item.domain);

  if (!mx.ok) {
    return {
      input: item.input,
      type: item.type,
      domain: item.domain,
      mx: "NO",
      mailHost: "",
      provider: "",
      status: item.type === "EMAIL" ? "NO_MX" : "NO_MX",
      message: "Domain has no usable MX records"
    };
  }

  const mailHost = mx.hosts[0];
  const provider = providerFor(mx.hosts);

  if (item.type === "DOMAIN") {
    return {
      input: item.input,
      type: "DOMAIN",
      domain: item.domain,
      mx: "YES",
      mailHost,
      provider,
      status: "MAIL_DOMAIN",
      message: `Mail hosting detected (${provider})`
    };
  }

  // SMTP is optional. It is best-effort and can be blocked by the network/provider.
  if (options.smtp === false) {
    return {
      input: item.input,
      type: "EMAIL",
      domain: item.domain,
      mx: "YES",
      mailHost,
      provider,
      status: "MX_ONLY",
      message: "MX is valid; SMTP mailbox verification was skipped"
    };
  }

  const smtp = await smtpVerify(mailHost, item.input, options);

  return {
    input: item.input,
    type: "EMAIL",
    domain: item.domain,
    mx: "YES",
    mailHost,
    provider,
    status: smtp.status,
    code: smtp.code || "",
    message: smtp.message
  };
}

async function mapLimit(items, limit, worker) {
  const results = new Array(items.length);
  let next = 0;

  async function runner() {
    while (true) {
      const index = next++;
      if (index >= items.length) return;
      try {
        results[index] = await worker(items[index], index);
      } catch (err) {
        results[index] = {
          input: String(items[index] ?? "").trim(),
          type: "INVALID",
          domain: "",
          mx: "NO",
          mailHost: "",
          provider: "",
          status: "ERROR",
          message: err.message || "Unexpected error"
        };
      }
    }
  }

  const runners = Array.from({ length: Math.min(limit, items.length) }, runner);
  await Promise.all(runners);
  return results;
}

app.post("/check", async (req, res) => {
  try {
    const rawInput = String(req.body?.input || "");
    const options = {
      smtp: req.body?.smtp !== false,
      timeoutMs: Math.min(Math.max(Number(req.body?.timeoutMs) || 7000, 2000), 15000),
      concurrency: Math.min(Math.max(Number(req.body?.concurrency) || 3, 1), 10)
    };

    const lines = [...new Set(
      rawInput
        .split(/\r?\n/)
        .map(s => s.trim())
        .filter(Boolean)
    )];

    if (!lines.length) {
      return res.status(400).json({ error: "Paste at least one email or domain." });
    }

    if (lines.length > 5000) {
      return res.status(400).json({ error: "Maximum 5,000 entries per request." });
    }

    const results = await mapLimit(lines, options.concurrency, item => checkOne(item, options));

    const stats = results.reduce((acc, r) => {
      acc.total++;
      acc[r.status] = (acc[r.status] || 0) + 1;
      return acc;
    }, { total: 0 });

    res.json({ results, stats });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Checker failed. See server console for details." });
  }
});

app.get("/health", (_req, res) => {
  res.json({ ok: true, service: "email-checker-upgraded" });
});

app.listen(PORT, () => {
  console.log(`Email Checker running at http://localhost:${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/health`);
});
