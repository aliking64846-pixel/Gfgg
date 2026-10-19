"use strict";

const os = require("node:os");
const dns = require("node:dns").promises;
const net = require("node:net");
const { execFile } = require("node:child_process");
const { promisify } = require("node:util");
const runFile = promisify(execFile);

const TOOL_PROBES = [
  { id: "nmap", label: "Nmap", command: "nmap", args: ["--version"], purpose: "فحص الشبكات المصرح بها" },
  { id: "curl", label: "curl", command: "curl", args: ["--version"], purpose: "اختبار اتصالات HTTP" },
  { id: "openssl", label: "OpenSSL", command: "openssl", args: ["version"], purpose: "معلومات TLS والشهادات" },
  { id: "python", label: "Python 3", command: process.platform === "win32" ? "python" : "python3", args: ["--version"], purpose: "أتمتة وتحليل دفاعي" },
  { id: "git", label: "Git", command: "git", args: ["--version"], purpose: "إدارة ملفات المشروع" }
];

async function detectTools() {
  return Promise.all(TOOL_PROBES.map(async tool => {
    try {
      const { stdout, stderr } = await runFile(tool.command, tool.args, {
        timeout: 1800, windowsHide: true, maxBuffer: 4096
      });
      return { id: tool.id, name: tool.label, available: true,
        version: String(stdout || stderr || "متوفر").trim().split(/\r?\n/)[0].slice(0, 180),
        purpose: tool.purpose };
    } catch {
      return { id: tool.id, name: tool.label, available: false,
        version: null, purpose: tool.purpose,
        installHint: tool.id === "nmap" ? "ثبّت Nmap من مدير الحزم الرسمي لنظامك إذا احتجته." : "ثبّت الأداة من مصدرها الرسمي عند الحاجة." };
    }
  }));
}

function getSystemSummary() {
  const interfaces = os.networkInterfaces();
  const network = [];
  for (const [name, entries] of Object.entries(interfaces)) {
    for (const item of entries || []) {
      network.push({
        interface: name,
        address: item.address,
        family: item.family,
        netmask: item.netmask,
        internal: Boolean(item.internal)
      });
    }
  }
  const totalMemory = os.totalmem();
  const freeMemory = os.freemem();
  return {
    ok: true,
    source: "live-local-operating-system",
    platform: os.platform(),
    release: os.release(),
    architecture: os.arch(),
    cpuCores: os.cpus().length,
    uptimeSeconds: Math.floor(os.uptime()),
    memory: {
      totalBytes: totalMemory,
      freeBytes: freeMemory,
      usedPercent: Math.round(((totalMemory - freeMemory) / totalMemory) * 100)
    },
    networkInterfaces: network,
    collectedAt: new Date().toISOString(),
    note: "معلومات النظام الحية على هذا الجهاز؛ لا تمثل مراقبة مستمرة أو حكماً بأن الجهاز آمن."
  };
}

async function resolveDomain(input) {
  if (typeof input !== "string" || input.length > 253) throw new Error("أدخل اسم نطاق صحيحاً.");
  const domain = input.trim().toLowerCase().replace(/\.$/, "");
  if (!domain || domain.includes("://") || domain.includes("/") || domain.includes("@") ||
      domain.includes(":") || !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain)) {
    throw new Error("أدخل اسم نطاق فقط، مثل example.com، دون مسار أو بروتوكول.");
  }
  const [v4, v6, mx] = await Promise.allSettled([
    dns.resolve4(domain), dns.resolve6(domain), dns.resolveMx(domain)
  ]);
  const addresses = result => result.status === "fulfilled" ? result.value : [];
  return {
    ok: true,
    mode: "real-dns-lookup",
    domain,
    ipv4: addresses(v4),
    ipv6: addresses(v6),
    mailServers: addresses(mx).map(x => ({ exchange: x.exchange, priority: x.priority })),
    checkedAt: new Date().toISOString(),
    note: "استعلام DNS فقط؛ لا يعني أن النطاق آمن أو خالٍ من الثغرات."
  };
}

function isScannableSingleIPv4(input) {
  if (net.isIP(input) !== 4) return false;
  const [a, b, c, d] = input.split(".").map(Number);
  if (a === 0 || a === 127 || a >= 224 || (a === 169 && b === 254) ||
      (a === 255 && b === 255 && c === 255 && d === 255)) return false;
  return true;
}

async function scanSingleHost(input, authorized) {
  if (authorized !== true) throw new Error("أكد صراحةً أنك تملك الهدف أو لديك إذن بفحصه.");
  if (typeof input !== "string" || !isScannableSingleIPv4(input.trim())) {
    throw new Error("أدخل عنوان IPv4 واحداً فقط. لا تُقبل أسماء نطاقات أو نطاقات شبكية.");
  }
  const target = input.trim();
  try {
    const { stdout } = await runFile("nmap", [
      "-n", "-Pn", "-sT", "-T2", "--top-ports", "20", "--host-timeout", "30s",
      "--max-retries", "1", "-oN", "-", target
    ], { timeout: 35000, windowsHide: true, maxBuffer: 1024 * 1024 });
    return {
      ok: true,
      mode: "real-nmap-limited-single-host",
      target,
      scope: "عنوان IPv4 واحد؛ أكثر 20 منفذاً شيوعاً فقط؛ لا اكتشاف نطاقات ولا استغلال.",
      output: String(stdout).slice(0, 24000),
      checkedAt: new Date().toISOString(),
      note: "المنفذ المفتوح ليس ثغرة بحد ذاته. افحص فقط هدفاً تملكه أو لديك إذن صريح لاختباره."
    };
  } catch (error) {
    if (error && error.code === "ENOENT") throw new Error("Nmap غير مثبت أو غير موجود في PATH. ثبّته محلياً ثم أعد المحاولة.");
    if (error && error.killed) throw new Error("توقف الفحص بسبب تجاوز المهلة المحددة (35 ثانية).");
    const output = error && error.stdout ? String(error.stdout).slice(0, 12000) : "";
    if (output) return {
      ok: true, mode: "real-nmap-limited-single-host", target,
      scope: "عنوان IPv4 واحد؛ أكثر 20 منفذاً شيوعاً فقط.",
      output, checkedAt: new Date().toISOString(),
      note: "أعاد Nmap مخرجات جزئية أو رمز خروج غير صفري؛ راجعها يدوياً."
    };
    throw new Error("تعذر تشغيل Nmap. تحقق من تثبيته وصلاحيات التشغيل.");
  }
}

module.exports = { detectTools, getSystemSummary, resolveDomain, scanSingleHost };
