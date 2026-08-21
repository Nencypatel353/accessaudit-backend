"""
Passive, read-only security checks -- security headers, cookie flags,
TLS configuration, mixed content, and information disclosure.

Deliberately does NOT include active testing (XSS/SQLi injection,
brute forcing, path fuzzing at scale). Every check here is either a
single GET request or a TLS handshake inspection -- nothing that
probes for exploitable behavior. See the project spec doc, Section
"Security scanning boundaries" for the reasoning.
"""
import ssl
import socket
import datetime
import httpx
from urllib.parse import urlparse

# A short, well-known list only -- not a large path-guessing wordlist.
SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/wp-config.php.bak",
    "/config.json",
    "/.aws/credentials",
]


async def run_security_scan(url: str, mixed_content: list) -> list[dict]:
    findings = []
    parsed = urlparse(url)
    host = parsed.hostname
    is_https = parsed.scheme == "https"

    async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
        try:
            resp = await client.get(url)
        except Exception as e:
            return [{
                "check_id": "connection", "category": "general", "severity": "high",
                "title": "Could not connect to site", "description": str(e), "passed": False,
            }]

        headers = {k.lower(): v for k, v in resp.headers.items()}

        # ---- 1. Security headers ----
        findings += _check_headers(headers)

        # ---- 2. Cookie flags ----
        findings += _check_cookies(resp)

        # ---- 3. Information disclosure ----
        findings += _check_info_disclosure(headers)

        # ---- 4. Exposed sensitive paths ----
        findings += await _check_exposed_paths(client, url)

    # ---- 5. TLS / certificate ----
    if is_https and host:
        findings += _check_tls(host)
    else:
        findings.append({
            "check_id": "https-enforced", "category": "tls", "severity": "high",
            "title": "Site not served over HTTPS", "description": "The URL was loaded over plain HTTP.",
            "passed": False,
        })

    # ---- 6. Mixed content (data gathered during the accessibility scan) ----
    findings += _check_mixed_content(mixed_content)

    return findings


def _check_headers(headers: dict) -> list[dict]:
    checks = [
        ("content-security-policy", "csp-header", "high", "Content-Security-Policy",
         "Mitigates XSS and data-injection by restricting what content the browser will execute."),
        ("strict-transport-security", "hsts-header", "high", "Strict-Transport-Security (HSTS)",
         "Forces browsers to always use HTTPS for this site, preventing downgrade attacks."),
        ("x-frame-options", "frame-options-header", "medium", "X-Frame-Options",
         "Prevents the site from being embedded in a hidden iframe (clickjacking)."),
        ("x-content-type-options", "content-type-options-header", "medium", "X-Content-Type-Options",
         "Stops the browser from MIME-sniffing responses as a different type than declared."),
        ("referrer-policy", "referrer-policy-header", "low", "Referrer-Policy",
         "Controls how much URL information leaks to other sites via the referrer header."),
        ("permissions-policy", "permissions-policy-header", "low", "Permissions-Policy",
         "Restricts access to browser features like camera, microphone, geolocation."),
    ]
    findings = []
    for header_name, check_id, severity, title, desc in checks:
        present = header_name in headers
        findings.append({
            "check_id": check_id, "category": "headers", "severity": severity,
            "title": title, "description": desc, "passed": present,
        })
    return findings


def _check_cookies(resp) -> list[dict]:
    findings = []
    cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
    if not cookies:
        return findings

    all_secure = all("secure" in c.lower() for c in cookies)
    all_httponly = all("httponly" in c.lower() for c in cookies)
    all_samesite = all("samesite" in c.lower() for c in cookies)

    findings.append({
        "check_id": "cookie-secure-flag", "category": "cookies", "severity": "high",
        "title": "Cookies use Secure flag",
        "description": "Cookies without Secure can be sent over unencrypted HTTP connections.",
        "passed": all_secure,
    })
    findings.append({
        "check_id": "cookie-httponly-flag", "category": "cookies", "severity": "medium",
        "title": "Cookies use HttpOnly flag",
        "description": "Cookies without HttpOnly are readable by JavaScript, making them stealable via XSS.",
        "passed": all_httponly,
    })
    findings.append({
        "check_id": "cookie-samesite-flag", "category": "cookies", "severity": "medium",
        "title": "Cookies use SameSite attribute",
        "description": "Cookies without SameSite are more exposed to cross-site request forgery (CSRF).",
        "passed": all_samesite,
    })
    return findings


def _check_info_disclosure(headers: dict) -> list[dict]:
    findings = []
    server_header = headers.get("server", "")
    powered_by = headers.get("x-powered-by", "")

    findings.append({
        "check_id": "server-header-disclosure", "category": "info_disclosure", "severity": "low",
        "title": "Server header does not reveal version",
        "description": f"Server header value: '{server_header or 'not present'}'. Specific version numbers help attackers target known vulnerabilities.",
        "passed": not any(char.isdigit() for char in server_header),
    })
    findings.append({
        "check_id": "powered-by-disclosure", "category": "info_disclosure", "severity": "low",
        "title": "X-Powered-By header not exposed",
        "description": "This header reveals the backend framework, which is unnecessary information for clients.",
        "passed": powered_by == "",
    })
    return findings


async def _check_exposed_paths(client: httpx.AsyncClient, base_url: str) -> list[dict]:
    findings = []
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    for path in SENSITIVE_PATHS:
        try:
            resp = await client.get(origin + path, timeout=5.0)
            exposed = resp.status_code == 200
        except Exception:
            exposed = False

        findings.append({
            "check_id": f"exposed-path-{path.strip('/').replace('/', '-')}",
            "category": "exposed_paths", "severity": "high",
            "title": f"Sensitive path not publicly exposed: {path}",
            "description": f"Checks whether {path} is reachable and returns content.",
            "passed": not exposed,
        })
    return findings


def _check_tls(host: str) -> list[dict]:
    findings = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                version = ssock.version()

        expire_str = cert.get("notAfter")
        expires = datetime.datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
        days_left = (expires - datetime.datetime.utcnow()).days

        findings.append({
            "check_id": "tls-cert-validity", "category": "tls", "severity": "high",
            "title": "TLS certificate is valid and not expiring soon",
            "description": f"Certificate expires in {days_left} days ({expire_str}).",
            "passed": days_left > 14,
        })
        findings.append({
            "check_id": "tls-modern-version", "category": "tls", "severity": "medium",
            "title": "Modern TLS version in use",
            "description": f"Negotiated protocol: {version}.",
            "passed": version in ("TLSv1.3", "TLSv1.2"),
        })
    except Exception as e:
        findings.append({
            "check_id": "tls-check-error", "category": "tls", "severity": "medium",
            "title": "Could not verify TLS configuration",
            "description": str(e), "passed": False,
        })
    return findings


def _check_mixed_content(insecure_resources: list) -> list[dict]:
    passed = len(insecure_resources) == 0
    sample = ", ".join(insecure_resources[:3]) if insecure_resources else "none found"
    return [{
        "check_id": "mixed-content", "category": "mixed_content", "severity": "medium",
        "title": "No insecure (HTTP) resources loaded on HTTPS page",
        "description": f"Insecure resources: {sample}",
        "passed": passed,
    }]


def calculate_security_score(findings: list[dict]) -> int:
    weights = {"high": 10, "medium": 5, "low": 2, "info": 1}
    penalty = sum(weights.get(f["severity"], 1) for f in findings if not f["passed"])
    return max(0, 100 - penalty)
