// CyberGuard: low-impact HTTPS posture check for explicitly authorized public websites.
// No port scanning, payload injection, crawling, redirects, or private-network access.
const dns = require("node:dns").promises;
const https = require("node:https");
const net = require("node:net");

function isPublicIPv4(ip) {
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  const [a,b,c] = p;
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 192 && b === 0) return false;
  if (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) return false;
  if (a === 203 && b === 0 && c === 113) return false;
  return true;
}

function isPublicIP(ip) {
  const family = net.isIP(ip);
  if (family === 4) return isPublicIPv4(ip);
  if (family !== 6) return false;
  const s = ip.toLowerCase();
  // Permit global unicast only; reject mapped IPv4 and special/documentation ranges.
  if (s.startsWith("::") || s.startsWith("::ffff:") || s.startsWith("fe8") ||
      s.startsWith("fe9") || s.startsWith("fea") || s.startsWith("feb") ||
      s.startsWith("fc") || s.startsWith("fd") || s === "::1" ||
      s.startsWith("2001:db8:") || s.startsWith("2001:10:")) return false;
  return /^2[0-9a-f]{3}:|^3[0-9a-f]{3}:/.test(s);
}

function checkHeaders(headers) {
  const tests = [
    ["strict-transport-security", "HSTS"],
    ["content-security-policy", "Content Security Policy"],
    ["x-content-type-options", "X-Content-Type-Options"],
    ["x-frame-options", "X-Frame-Options"],
    ["referrer-policy", "Referrer-Policy"]
  ];
  return tests.map(([key, label]) => ({
    header: label,
    present: Boolean(headers[key]),
    value: headers[key] ? String(headers[key]).slice(0, 300) : null,
    severity: headers[key] ? "info" : (key === "strict-transport-security" ? "medium" : "low")
  }));
}

async function checkWebsite(input) {
  if (typeof input !== "string" || input.length > 2048) throw new Error("أدخل رابطاً صحيحاً.");
  let url;
  try { url = new URL(input.includes("://") ? input : "https://" + input); }
  catch { throw new Error("صيغة الرابط غير صحيحة."); }
  if (url.protocol !== "https:") throw new Error("الفحص الحالي يقبل HTTPS فقط.");
  if (url.username || url.password || url.port && url.port !== "443") throw new Error("اسم مستخدم أو منفذ غير مسموح.");
  if (url.hostname === "localhost" || url.hostname.endsWith(".localhost") || url.hostname.endsWith(".local")) {
    throw new Error("العناوين المحلية غير مسموحة في هذا الفحص.");
  }
  const host = url.hostname.replace(/^\[|\]$/g, "");
  let addresses;
  if (net.isIP(host)) addresses = [{ address: host, family: net.isIP(host) }];
  else {
    addresses = await dns.lookup(host, { all: true, verbatim: true });
  }
  if (!addresses.length || addresses.some(item => !isPublicIP(item.address))) {
    throw new Error("رُفض الفحص لأن العنوان لا يُحل إلى عناوين عامة مسموحة فقط.");
  }
  const chosen = addresses[0];
  const started = Date.now();
  const result = await new Promise((resolve, reject) => {
    const req = https.request({
      protocol: "https:",
      hostname: host,
      servername: net.isIP(host) ? undefined : host,
      port: 443,
      path: url.pathname + url.search,
      method: "GET",
      timeout: 7000,
      maxHeaderSize: 16384,
      headers: { "User-Agent": "CyberGuard-Authorized-Posture-Check/1.0", "Range": "bytes=0-0" },
      lookup: (_hostname, _options, callback) => callback(null, chosen.address, chosen.family),
      rejectUnauthorized: true
    }, res => {
      // Headers are the only data needed; close immediately so a server cannot stream a huge body.
      resolve({ status: res.statusCode, headers: res.headers });
      res.destroy();
    });
    req.on("timeout", () => req.destroy(new Error("انتهت مهلة الاتصال.")));
    req.on("error", reject);
    req.end();
  });
  return {
    ok: true,
    mode: "real-low-impact-https-check",
    target: url.origin,
    resolvedAddress: chosen.address,
    httpStatus: result.status,
    elapsedMs: Date.now() - started,
    checkedAt: new Date().toISOString(),
    findings: checkHeaders(result.headers),
    limitations: "فحص أولي للترويسات فقط؛ لا يثبت خلو الموقع من الثغرات. لم تُفحص المسارات أو تُرسل حمولات اختبارية."
  };
}

module.exports = { checkWebsite };
