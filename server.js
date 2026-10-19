"use strict";

const express = require("express");
const path = require("node:path");
const { detectTools, getSystemSummary, resolveDomain, scanSingleHost } = require("./lab-tools");
const app = express();
const PORT = Number(process.env.PORT || 3000);
const SCANS_ENABLED = process.env.CYBERGUARD_ENABLE_SCANS === "true";

app.disable("x-powered-by");
app.use(express.json({ limit: "100kb" }));
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  res.setHeader("Cache-Control", "no-store");
  next();
});

app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    service: "CyberGuard Local Lab",
    mode: SCANS_ENABLED ? "local-authorized-tools-enabled" : "local-diagnostics-only",
    websiteChecksEnabled: SCANS_ENABLED,
    networkScansEnabled: SCANS_ENABLED,
    timestamp: new Date().toISOString()
  });
});

// These diagnostics read the operating system where CyberGuard is running.
// The server binds only to loopback; this information is not exposed to the LAN.
app.get("/api/lab/status", async (_req, res) => {
  try {
    res.json({
      ok: true,
      localOnly: true,
      scansEnabled: SCANS_ENABLED,
      tools: await detectTools(),
      checkedAt: new Date().toISOString()
    });
  } catch {
    res.status(500).json({ ok: false, error: "تعذر قراءة حالة الأدوات المحلية." });
  }
});

app.get("/api/lab/system", (_req, res) => {
  res.json(getSystemSummary());
});

app.post("/api/lab/dns", async (req, res) => {
  try {
    res.json(await resolveDomain(req.body?.domain));
  } catch (error) {
    res.status(400).json({
      ok: false,
      error: error instanceof Error ? error.message : "تعذر تنفيذ استعلام DNS."
    });
  }
});

// Network scans are opt-in and restricted to one IPv4 address per request.
if (SCANS_ENABLED) {
  const { checkWebsite } = require("./site-check");

  app.post("/api/check-website", async (req, res) => {
    if (req.body?.authorized !== true) {
      return res.status(403).json({ error: "أكد أن لديك ملكية الموقع أو تصريحاً صريحاً لفحصه." });
    }
    try {
      res.json(await checkWebsite(req.body?.target));
    } catch (error) {
      res.status(400).json({
        ok: false,
        error: error instanceof Error ? error.message : "تعذر إجراء الفحص."
      });
    }
  });

  app.post("/api/lab/nmap", async (req, res) => {
    try {
      res.json(await scanSingleHost(req.body?.target, req.body?.authorized));
    } catch (error) {
      const missingTool = error instanceof Error && /Nmap غير مثبت/.test(error.message);
      res.status(missingTool ? 503 : 400).json({
        ok: false,
        error: error instanceof Error ? error.message : "تعذر تشغيل الفحص المحدود."
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
  console.log(`CyberGuard Local Lab listening on http://127.0.0.1:${PORT}`);
});
