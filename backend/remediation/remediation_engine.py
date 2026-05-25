"""
Auto-Remediation Engine.

Provides concrete, copy-paste-ready configuration snippets and code examples
for each class of vulnerability detected by the framework.
"""
from functools import lru_cache
from typing import Dict, List

from backend.detectors.base import VulnerabilityFinding
from backend.utils.logger import get_logger

logger = get_logger(__name__)


# ── Remediation templates ─────────────────────────────────────────────────────

_REMEDIATIONS: Dict[str, dict] = {

    "SQL Injection": {
        "summary": "Use parameterised queries and input validation.",
        "code_examples": {
            "Python (SQLAlchemy)": """
# VULNERABLE
query = f"SELECT * FROM users WHERE name = '{user_input}'"

# SECURE — use parameterised queries
from sqlalchemy import text
result = db.execute(text("SELECT * FROM users WHERE name = :name"), {"name": user_input})
""",
            "Python (sqlite3)": """
# SECURE
conn.execute("SELECT * FROM users WHERE name = ?", (user_input,))
""",
            "PHP (PDO)": """
// SECURE
$stmt = $pdo->prepare("SELECT * FROM users WHERE name = ?");
$stmt->execute([$user_input]);
""",
        },
        "config_examples": {
            "ModSecurity WAF Rule": "SecRule ARGS \"@detectSQLi\" \"id:1000,phase:2,deny,log\"",
        },
        "hardening_steps": [
            "Implement input validation with an allowlist for each field.",
            "Use an ORM and avoid raw SQL string concatenation.",
            "Apply least-privilege to database accounts (no DROP/ALTER).",
            "Enable ModSecurity or AWS WAF with the SQL injection rule set.",
            "Review all query construction points in the codebase.",
        ],
    },

    "XSS": {
        "summary": "Encode all output and implement a Content-Security-Policy.",
        "code_examples": {
            "Python (Jinja2 — auto-escape)": """
# Enable auto-escaping in Jinja2 (default for .html templates)
from jinja2 import Environment
env = Environment(autoescape=True)

# Explicit escaping
from markupsafe import escape
safe_output = escape(user_input)
""",
            "JavaScript (DOM)": """
// VULNERABLE
element.innerHTML = userInput;

// SECURE
element.textContent = userInput;
""",
        },
        "config_examples": {
            "Nginx CSP Header": (
                'add_header Content-Security-Policy "default-src \'self\'; '
                'script-src \'self\' \'nonce-{RANDOM}\'" always;'
            ),
            "Apache CSP Header": (
                'Header always set Content-Security-Policy "default-src \'self\'"'
            ),
        },
        "hardening_steps": [
            "Use templating engines with auto-escaping enabled.",
            "Deploy a strict Content-Security-Policy.",
            "Apply X-XSS-Protection: 1; mode=block.",
            "Sanitise rich-text input with a library like DOMPurify.",
            "Avoid eval(), document.write(), and innerHTML with user data.",
        ],
    },

    "Missing Security Header": {
        "summary": "Add HTTP security headers in web-server configuration.",
        "code_examples": {
            "FastAPI middleware": """
from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response: Response = await call_next(request)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response

app = FastAPI()
app.add_middleware(SecurityHeadersMiddleware)
""",
        },
        "config_examples": {
            "Nginx": """
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Content-Security-Policy "default-src 'self'" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
""",
            "Apache (.htaccess)": """
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header always set X-Content-Type-Options "nosniff"
Header always set X-Frame-Options "DENY"
Header always set Content-Security-Policy "default-src 'self'"
""",
        },
        "hardening_steps": [
            "Apply headers globally in your web-server configuration.",
            "Test header configuration at https://securityheaders.com",
            "Add headers to your CDN (CloudFront, Cloudflare) as well.",
        ],
    },

    "Weak SSL/TLS Configuration": {
        "summary": "Enforce TLS 1.2+ with strong cipher suites.",
        "code_examples": {},
        "config_examples": {
            "Nginx TLS hardening": """
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers off;
ssl_session_timeout 1d;
ssl_session_cache shared:MozSSL:10m;
ssl_stapling on;
ssl_stapling_verify on;
""",
            "Apache TLS hardening": """
SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
SSLHonorCipherOrder off
SSLSessionTickets off
""",
        },
        "hardening_steps": [
            "Disable SSLv2, SSLv3, TLSv1.0, and TLSv1.1.",
            "Use only AEAD cipher suites with PFS (ECDHE, DHE).",
            "Automate certificate renewal (Let's Encrypt / Certbot).",
            "Enable HSTS with includeSubDomains.",
            "Test configuration with Qualys SSL Labs (ssllabs.com/ssltest/).",
        ],
    },

    "Dangerous Open Port": {
        "summary": "Close unnecessary ports and restrict access with firewall rules.",
        "code_examples": {},
        "config_examples": {
            "iptables (Linux)": """
# Block external access to Redis (allow only localhost)
iptables -A INPUT -s 127.0.0.1 -p tcp --dport 6379 -j ACCEPT
iptables -A INPUT -p tcp --dport 6379 -j DROP

# Block Telnet (port 23) entirely
iptables -A INPUT -p tcp --dport 23 -j DROP
""",
            "UFW (Ubuntu)": """
sudo ufw deny 23/tcp        # Block Telnet
sudo ufw deny 6379/tcp      # Block Redis external access
sudo ufw allow from 192.168.1.0/24 to any port 3306  # MySQL: internal only
""",
        },
        "hardening_steps": [
            "Audit all listening services with: ss -tlnp (Linux) or netstat -ano (Windows).",
            "Stop and disable unnecessary services.",
            "Apply default-deny firewall policy; whitelist required ports only.",
            "Use network segmentation — place databases in a private subnet.",
            "Regularly scan your perimeter with nmap to detect new services.",
        ],
    },

    "Weak SSH Configuration": {
        "summary": "Harden sshd_config and upgrade OpenSSH.",
        "code_examples": {},
        "config_examples": {
            "/etc/ssh/sshd_config hardening": """
Protocol 2
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
AllowUsers youradminuser
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
AllowTcpForwarding no
Banner /etc/issue.net
LogLevel VERBOSE
""",
        },
        "hardening_steps": [
            "Upgrade OpenSSH to the latest stable release.",
            "Disable password authentication; use SSH keys only.",
            "Disable root login (PermitRootLogin no).",
            "Restrict SSH access to specific users/IPs.",
            "Use Fail2Ban to block brute-force attempts.",
            "Rotate SSH host keys periodically.",
        ],
    },

    "Directory Traversal": {
        "summary": "Validate file paths against an allowlist and use chroot/containers.",
        "code_examples": {
            "Python — safe file path validation": """
import os
from pathlib import Path

WEB_ROOT = Path("/var/www/html").resolve()

def safe_open(user_path: str):
    requested = (WEB_ROOT / user_path).resolve()
    if not str(requested).startswith(str(WEB_ROOT)):
        raise PermissionError("Path traversal attempt detected.")
    return requested.read_text()
""",
        },
        "config_examples": {},
        "hardening_steps": [
            "Resolve canonical paths and verify they start within the expected root.",
            "Use an allowlist of permitted filenames rather than blocking traversal sequences.",
            "Run the web application in a chroot jail or container.",
            "Strip ../ sequences from all user-supplied file paths.",
            "Disable directory listing in web-server configuration.",
        ],
    },

    "Insecure HTTP Methods": {
        "summary": "Restrict HTTP methods in web-server configuration.",
        "code_examples": {},
        "config_examples": {
            "Nginx": """
# Allow only GET, POST, HEAD; block everything else
if ($request_method !~ ^(GET|POST|HEAD)$) {
    return 405;
}
""",
            "Apache": """
<LimitExcept GET POST HEAD>
    deny from all
</LimitExcept>
""",
        },
        "hardening_steps": [
            "Explicitly allow only the HTTP methods required by your application.",
            "Return HTTP 405 for all disallowed methods.",
            "Disable WebDAV if not needed (prevents PUT/DELETE).",
            "Log and alert on requests using unusual HTTP methods.",
        ],
    },

    "Information Disclosure": {
        "summary": "Suppress server version information from responses.",
        "code_examples": {},
        "config_examples": {
            "Nginx": "server_tokens off;",
            "Apache": "ServerTokens Prod\nServerSignature Off",
            "PHP": "expose_php = Off",
        },
        "hardening_steps": [
            "Disable server version banners in all layers (web server, app server, DB).",
            "Return generic error pages — never expose stack traces.",
            "Remove X-Powered-By and other technology-revealing headers.",
            "Use a WAF to filter outbound error details.",
        ],
    },
}


_GENERIC_REMEDIATION = {
    "summary": "Apply defence-in-depth practices and review OWASP guidelines.",
    "code_examples": {},
    "config_examples": {},
    "hardening_steps": [
        "Review OWASP Top 10 for guidance.",
        "Apply vendor security patches regularly.",
        "Conduct periodic penetration tests in authorised environments.",
    ],
}


@lru_cache(maxsize=64)
def _cached_remediation(vuln_type: str) -> dict:
    """Memoised remediation lookup — registry is read-only at runtime."""
    return _REMEDIATIONS.get(vuln_type) or _GENERIC_REMEDIATION


class RemediationEngine:
    """Produce structured remediation guidance for vulnerability findings."""

    def get_remediation(self, vuln_type: str) -> dict:
        """
        Return full remediation data for *vuln_type*.
        Falls back to a generic response if the type is not in the knowledge base.
        """
        return _cached_remediation(vuln_type)

    def enrich_finding(self, finding: VulnerabilityFinding) -> VulnerabilityFinding:
        """Attach remediation data to the finding's fix list if it is sparse."""
        if len(finding.fix) < 3:
            remediation = self.get_remediation(finding.vuln_type)
            finding.fix = remediation["hardening_steps"]
        return finding

    def generate_report_section(self, findings: List[VulnerabilityFinding]) -> List[dict]:
        """Build a remediation section suitable for inclusion in a PDF report."""
        seen: set = set()
        sections = []
        for f in findings:
            if f.vuln_type not in seen:
                seen.add(f.vuln_type)
                rem = self.get_remediation(f.vuln_type)
                sections.append({
                    "vuln_type": f.vuln_type,
                    "summary": rem["summary"],
                    "hardening_steps": rem["hardening_steps"],
                    "code_examples": rem.get("code_examples", {}),
                    "config_examples": rem.get("config_examples", {}),
                })
        return sections
