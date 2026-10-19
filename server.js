const express = require("express");
const path = require("path");
const app = express();
const PORT = process.env.PORT || 3000;

app.disable("x-powered-by");
app.use(express.json({ limit: "100kb" }));
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  next();
});

app.get("/api/health", (_req, res) => {
  res.json({ ok: true, service: "CyberGuard API", mode: "educational", timestamp: new Date().toISOString() });
});

// Defensive log parsing only: no active scanning or remote-target interaction.
app.post("/api/analyze-logs", (req, res) => {
  const raw = typeof req.body?.logs === "string" ? req.body.logs : "";
  if (!raw.trim()) return res.status(400).json({ error: "أرسل نص السجلات داخل الحقل logs." });
  if (raw.length > 80000) return res.status(413).json({ error: "حجم السجلات أكبر من الحد المسموح (80KB)." });
  const lines = raw.split(/\r?\n/).filter(Boolean);
  const failed = lines.filter(line => /fail(?:ed)?|denied|unauthori[sz]ed|login error|رفض|فشل/i.test(line)).length;
  const warnings = lines.filter(line => /warn(?:ing)?|error|invalid|critical|alert|تحذير|خطأ|حرج/i.test(line)).length;
  const ips = [...new Set(raw.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [])].filter(ip => ip.split(".").every(n => Number(n) <= 255));
  res.json({
    ok: true,
    disclaimer: "تحليل نصي أولي فقط؛ ليس حكماً أمنياً نهائياً ولا يكشف الهجمات وحده.",
    lineCount: lines.length,
    possibleFailedEvents: failed,
    possibleWarnings: warnings,
    ipv4AddressesMentioned: ips,
    nextSteps: [
      "تحقق من الطابع الزمني والحساب ومصدر السجل.",
      "قارن الأحداث بمصادر سجلات موثوقة أخرى.",
      "لا تحظر عنواناً أو تعزل جهازاً بناءً على هذا التحليل وحده."
    ]
  });
});

// Serve the web app from the repository root when running the API server.
app.use(express.static(path.join(__dirname)));
app.get("*", (_req, res) => res.sendFile(path.join(__dirname, "index.html")));

app.listen(PORT, () => console.log(`CyberGuard API listening on port ${PORT}`));
