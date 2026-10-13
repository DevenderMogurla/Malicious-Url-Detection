import os, re, ipaddress, socket, hashlib
from urllib.parse import urlparse, unquote
from flask import Flask, request, jsonify, render_template
import requests

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False
TIMEOUT = 5
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc"
}
SUSPICIOUS_WORDS = {
    "login", "verify", "verification", "secure", "account", "update",
    "password", "wallet", "banking", "signin", "confirm", "bonus",
    "free-gift", "gift", "prize", "urgent", "suspended", "recover"
}
DANGEROUS_EXTENSIONS = (".exe", ".scr", ".bat", ".cmd", ".msi", ".apk", ".js", ".vbs", ".ps1")
KNOWN_SAFE_SCHEMES = {"http", "https"}

def normalize_url(raw):
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("Enter a URL to analyze.")
    if any(ord(ch) < 32 for ch in raw):
        raise ValueError("URL contains control characters.")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        raw = "https://" + raw
    parsed = urlparse(raw)
    if parsed.scheme.lower() not in KNOWN_SAFE_SCHEMES:
        raise ValueError("Only HTTP and HTTPS links can be checked.")
    if not parsed.hostname:
        raise ValueError("That does not look like a valid URL. Include a domain such as example.com.")
    try:
        _ = parsed.port
    except ValueError:
        raise ValueError("The URL contains an invalid port.")
    return raw, parsed

def google_safe_browsing_check(url):
    if not GOOGLE_SAFE_BROWSING_API_KEY:
        return {"configured": False, "status": "not_configured",
                "message": "Google Safe Browsing is not configured. Add an API key to enable this check."}
    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    payload = {
        "client": {"clientId": "malicious-url-detector", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        response = requests.post(endpoint, params={"key": GOOGLE_SAFE_BROWSING_API_KEY},
                                 json=payload, timeout=TIMEOUT)
        if response.status_code == 200:
            data = response.json()
            matches = data.get("matches", [])
            return {"configured": True, "status": "malicious" if matches else "clean",
                    "matches": [{"threatType": x.get("threatType", "UNKNOWN")} for x in matches],
                    "message": "Threat match found." if matches else "No match in Google Safe Browsing for this URL."}
        return {"configured": True, "status": "error",
                "message": f"Google Safe Browsing returned HTTP {response.status_code}."}
    except requests.RequestException:
        return {"configured": True, "status": "error", "message": "Google Safe Browsing could not be reached."}

def analyze_url(raw):
    normalized, parsed = normalize_url(raw)
    host = (parsed.hostname or "").lower().rstrip(".")
    decoded = unquote(normalized).lower()
    findings = []
    score = 0

    def flag(points, severity, title, detail):
        nonlocal score
        score += points
        findings.append({"severity": severity, "title": title, "detail": detail})

    if parsed.scheme.lower() != "https":
        flag(10, "medium", "No HTTPS", "The link uses HTTP, so the connection may not be encrypted.")
    if "@" in parsed.netloc:
        flag(25, "high", "Misleading @ symbol", "Text before @ can disguise the destination host.")
    if len(normalized) > 180:
        flag(10, "medium", "Unusually long URL", "Long links can hide the real destination or encode tracking and redirect data.")
    if len(host) > 50:
        flag(8, "low", "Long hostname", "The hostname is unusually long.")
    if host.startswith("xn--") or ".xn--" in host:
        flag(18, "high", "Internationalized hostname", "Punycode can be used for look-alike domain names. Inspect the displayed domain carefully.")
    try:
        ipaddress.ip_address(host)
        flag(20, "high", "IP address used as host", "The link points directly to an IP address instead of a typical domain name.")
    except ValueError:
        pass
    if host in SHORTENERS:
        flag(15, "medium", "URL shortener", "The final destination is hidden behind a URL-shortening service.")
    if host.count("-") >= 3:
        flag(8, "low", "Many hyphens in hostname", "Multiple hyphens can be a sign of a deceptive look-alike domain.")
    if host.count(".") >= 4:
        flag(8, "low", "Many subdomains", "Several subdomains may make the actual registered domain harder to notice.")
    if any(word in decoded for word in SUSPICIOUS_WORDS):
        flag(12, "medium", "Credential or urgency wording", "The URL contains wording often used in phishing lures, such as login, verify, urgent, or account.")
    if parsed.username or parsed.password:
        flag(25, "high", "Embedded credentials", "The URL includes username/password fields before the host.")
    path = (parsed.path or "").lower()
    if path.endswith(DANGEROUS_EXTENSIONS):
        flag(25, "high", "Potentially risky download", "The URL path ends in an executable or script-like file extension.")
    if re.search(r"%[0-9a-f]{2}", normalized, re.I):
        flag(4, "low", "Percent-encoded characters", "The URL contains encoded characters; this is common but can obscure its meaning.")
    if host.count(".") == 0 and host not in {"localhost"}:
        flag(10, "medium", "Unusual hostname format", "The hostname does not contain a dot.")
    if not findings:
        findings.append({"severity": "info", "title": "No obvious heuristic warning", "detail": "The URL did not trigger the local pattern checks. This is not proof that it is safe."})

    reputation = google_safe_browsing_check(normalized)
    if reputation.get("status") == "malicious":
        flag(70, "critical", "Threat reputation match", "Google Safe Browsing reports a known threat for this URL.")
    score = min(score, 100)
    if reputation.get("status") == "malicious" or score >= 60:
        verdict, label = "dangerous", "Dangerous / high risk"
    elif score >= 25:
        verdict, label = "suspicious", "Suspicious / review carefully"
    else:
        verdict, label = "lower_risk", "No obvious threat detected"

    try:
        ascii_host = host.encode("idna").decode("ascii")
    except Exception:
        ascii_host = host
    return {
        "input": raw, "normalized_url": normalized, "hostname": host,
        "ascii_hostname": ascii_host, "scheme": parsed.scheme.lower(),
        "risk_score": score, "verdict": verdict, "verdict_label": label,
        "findings": findings, "reputation": reputation,
        "url_sha256": hashlib.sha256(normalized.encode("utf-8")).hexdigest(),
        "disclaimer": "This is a risk assessment, not a guarantee. New or targeted malicious links may not be listed or trigger heuristics. Do not open links you suspect are harmful."
    }

@app.get("/")
def index():
    return render_template("index.html")

@app.post("/api/scan")
def scan():
    data = request.get_json(silent=True) or request.form
    try:
        result = analyze_url(data.get("url", ""))
        return jsonify(result)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "google_safe_browsing_configured": bool(GOOGLE_SAFE_BROWSING_API_KEY)})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", "5000")), debug=False)
