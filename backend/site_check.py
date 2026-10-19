"""Low-impact local website posture checks for authorized targets.

This module is intentionally limited to DNS and HTTP HEAD/header checks.
It does not exploit vulnerabilities or scan ports.
"""
from __future__ import annotations
import ipaddress
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _resolve_public(host: str) -> str:
    answers = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    if not answers:
        raise ValueError("تعذّر حل اسم النطاق.")
    ips = list(dict.fromkeys(item[4][0] for item in answers))
    parsed = [ipaddress.ip_address(ip) for ip in ips]
    if any(not ip.is_global for ip in parsed):
        raise ValueError("أُوقف الفحص: النطاق يحلّ إلى عنوان خاص أو محجوز أو غير عام.")
    return ips[0]


def scan_site(target: str, authorized: bool = False) -> dict:
    if not authorized:
        raise PermissionError("أكد أنك تملك الموقع أو لديك إذن صريح بفحصه.")
    raw = target.strip()
    if not raw:
        raise ValueError("أدخل عنوان موقع.")
    if "://" not in raw:
        raw = "https://" + raw
    url = urllib.parse.urlsplit(raw)
    if url.scheme not in ("http", "https") or not url.hostname or url.username or url.password:
        raise ValueError("المسموح عنوان HTTP أو HTTPS صحيح دون بيانات دخول.")
    if url.port not in (None, 80, 443):
        raise ValueError("الإصدار الأول يسمح بمنافذ الويب القياسية 80 و443 فقط.")
    ip = _resolve_public(url.hostname)
    context = ssl.create_default_context()
    request = urllib.request.Request(raw, method="HEAD", headers={"User-Agent": "CyberGuard-Local-Check/1.0"})
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=context))
    try:
        response = opener.open(request, timeout=8)
        status, headers = response.status, response.headers
    except urllib.error.HTTPError as exc:
        # A 3xx redirect or 4xx/5xx response is recorded, not followed.
        status, headers = exc.code, exc.headers
    checks = [
        {"name": "Strict-Transport-Security", "ok": url.scheme != "https" or bool(headers.get("Strict-Transport-Security"))},
        {"name": "Content-Security-Policy", "ok": bool(headers.get("Content-Security-Policy"))},
        {"name": "X-Content-Type-Options: nosniff", "ok": "nosniff" in (headers.get("X-Content-Type-Options", "").lower())},
        {"name": "حماية تضمين الصفحة", "ok": bool(headers.get("X-Frame-Options")) or "frame-ancestors" in (headers.get("Content-Security-Policy", "").lower())},
        {"name": "Referrer-Policy", "ok": bool(headers.get("Referrer-Policy"))},
        {"name": "Permissions-Policy", "ok": bool(headers.get("Permissions-Policy"))},
    ]
    return {
        "ok": True,
        "scanType": "actual-limited-check",
        "label": "فحص فعلي محدود لطلب HEAD وترويسات الحماية",
        "target": f"{url.scheme}://{url.netloc}",
        "checkedAt": datetime.now(timezone.utc).isoformat(),
        "resolvedAddress": ip,
        "httpStatus": status,
        "score": round(100 * sum(c["ok"] for c in checks) / len(checks)),
        "scoreMeaning": "نسبة الترويسات التي ظهرت فقط، وليست درجة أمان شاملة.",
        "checks": checks,
        "limitations": [
            "لا يجري استغلالاً أو اختبار حقن أو تخمين كلمات مرور.",
            "غياب ترويسة لا يثبت وحده وجود ثغرة.",
            "بعض المواقع لا تدعم HEAD؛ راجع النتيجة يدوياً.",
            "لا يشمل هذا الاختبار ملفات الموقع أو إعدادات الخادم الداخلية.",
        ],
    }
