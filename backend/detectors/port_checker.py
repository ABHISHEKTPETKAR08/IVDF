"""
Dangerous Open-Port Checker.

Flags ports that are commonly exploited or should not be exposed in production.
"""
from typing import Dict, List

from backend.detectors.base import Severity, VulnerabilityFinding
from backend.utils.logger import get_logger

logger = get_logger(__name__)

# (port, service_name, severity, reason, owasp, cvss)
_DANGEROUS_PORTS: List[tuple] = [
    (21,    "FTP",              Severity.HIGH,     "Transmits credentials in plaintext.",                           "A02:2021", 7.5),
    (23,    "Telnet",           Severity.CRITICAL, "Unencrypted remote shell; full credential exposure.",          "A02:2021", 9.8),
    (25,    "SMTP",             Severity.MEDIUM,   "Open relay risk enables spam and phishing.",                    "A05:2021", 5.3),
    (445,   "SMB",              Severity.CRITICAL, "EternalBlue / WannaCry attack surface.",                       "A06:2021", 9.8),
    (1433,  "MSSQL",            Severity.HIGH,     "Database port exposed to network.",                             "A05:2021", 8.1),
    (1521,  "Oracle DB",        Severity.HIGH,     "Database port exposed to network.",                             "A05:2021", 8.1),
    (2375,  "Docker API",       Severity.CRITICAL, "Unauthenticated Docker daemon; full host compromise.",         "A05:2021", 9.8),
    (2376,  "Docker TLS API",   Severity.HIGH,     "Docker daemon TLS may be misconfigured.",                      "A05:2021", 8.0),
    (3306,  "MySQL",            Severity.HIGH,     "Database port exposed to network.",                             "A05:2021", 8.1),
    (3389,  "RDP",              Severity.HIGH,     "Remote Desktop susceptible to brute-force and BlueKeep.",      "A06:2021", 8.1),
    (4444,  "Metasploit Shell", Severity.CRITICAL, "Default Metasploit reverse-shell port — likely compromised.", "A06:2021", 9.9),
    (5432,  "PostgreSQL",       Severity.HIGH,     "Database port exposed to network.",                             "A05:2021", 8.1),
    (5900,  "VNC",              Severity.HIGH,     "Remote desktop; often weakly authenticated.",                  "A07:2021", 7.5),
    (6379,  "Redis",            Severity.CRITICAL, "Unauthenticated Redis allows arbitrary writes.",               "A07:2021", 9.8),
    (8080,  "HTTP Alternate",   Severity.LOW,      "Non-standard HTTP port; may expose dev/admin interfaces.",     "A05:2021", 4.0),
    (27017, "MongoDB",          Severity.CRITICAL, "Unauthenticated MongoDB allows full data access.",             "A07:2021", 9.8),
    # ── Additional high-impact ports ───────────────────────────────────────
    (2049,  "NFS",              Severity.HIGH,     "Network File System exposed; unauthenticated mounts possible.","A05:2021", 7.5),
    (5601,  "Kibana",           Severity.HIGH,     "Kibana dashboard often unauthenticated; reveals indexed data.","A07:2021", 8.0),
    (5984,  "CouchDB",          Severity.HIGH,     "CouchDB admin API may be exposed without authentication.",     "A07:2021", 8.1),
    (9200,  "Elasticsearch",    Severity.CRITICAL, "Elasticsearch REST API typically unauthenticated by default.", "A07:2021", 9.8),
    (9300,  "Elasticsearch TCP", Severity.HIGH,    "Elasticsearch transport port — cluster join attack surface.",  "A05:2021", 7.8),
    (11211, "Memcached",        Severity.HIGH,     "Memcached has no auth; used in massive UDP amplification DDoS.","A05:2021", 8.6),
    (15672, "RabbitMQ Mgmt",    Severity.MEDIUM,   "RabbitMQ management UI; default creds guest:guest common.",    "A07:2021", 6.5),
    (50070, "Hadoop NameNode",  Severity.HIGH,     "Hadoop HDFS admin UI often unauthenticated.",                  "A05:2021", 7.5),
]

_PORT_MAP: Dict[int, tuple] = {entry[0]: entry for entry in _DANGEROUS_PORTS}


class DangerousPortChecker:
    """Compare discovered open ports against a list of dangerous services."""

    def detect(self, open_ports: List[int]) -> List[VulnerabilityFinding]:
        """
        Given a list of *open_ports*, return findings for each dangerous port.
        """
        findings: List[VulnerabilityFinding] = []
        for port in open_ports:
            if port in _PORT_MAP:
                _, svc, severity, reason, owasp, cvss = _PORT_MAP[port]
                findings.append(
                    VulnerabilityFinding(
                        name=f"Dangerous Open Port: {port}/{svc}",
                        vuln_type="Dangerous Open Port",
                        severity=severity,
                        explanation=f"Port {port} ({svc}) is open and reachable. {reason}",
                        technical_description=(
                            f"Service '{svc}' is listening on port {port}. "
                            "Exposing this port increases the attack surface."
                        ),
                        impact=reason,
                        fix=[
                            f"Close port {port} if the service is not required.",
                            "Restrict access via firewall rules to trusted IPs only.",
                            "Place the service behind a VPN or bastion host.",
                            "Enable authentication and encryption for the service.",
                        ],
                        owasp_mapping=f"{owasp} – Security Misconfiguration",
                        cvss_score=cvss,
                        affected_port=port,
                    )
                )
        return findings
