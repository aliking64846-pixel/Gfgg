const express = require("express");
const path = require("path");
const app = express();
const PORT = process.env.PORT || 3000;
const SCANS_ENABLED = process.env.CYBERGUARD_ENABLE_SCANS === "true";

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
  res.json({
    ok: true,
    service: "CyberGuard API",
    mode: SCANS_ENABLED ? "local-authorized-checks-enabled" : "educational",
    websiteChecksEnabled: SCANS_ENABLED,
    timestamp: new Date().toISOString()
  });
});

// Low-impact HTTPS posture check. Explicit opt-in prevents accidental activation on public deployments.
if (SCANS_ENABLED) {
  const { checkWebsite } = require("./site-check");
  app.post("/api/check-website", async (req, res) => {
    if (req.body?.authorized !== true) {
      return res.status(403).json({ error: "أكد أن لديك ملكية الموقع أو تصريحاً صريحاً لفحصه." });
    }
    try {
      const result = await checkWebsite(req.body?.target);
      res.json(result);
    } catch (error) {
      res.status(400).json({
        ok: false,
        error: error instanceof Error ? error.message : "تعذر إجراء الفحص."
      });
    }
  });
}

// Defensive log parsing only: local text analysis, not a definitive detection engine.
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

app.use(express.static(path.join(__dirname)));
app.get("*", (_req, res) => res.sendFile(path.join(__dirname, "index.html")));

app.listen(PORT, "127.0.0.1", () => {
  console.log(`CyberGuard API listening locally on http://127.0.0.1:${PORT}`);
});
