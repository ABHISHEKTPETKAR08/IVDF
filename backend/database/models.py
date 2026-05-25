"""
SQLAlchemy ORM models for the Vulnerability Scanner Framework.
Supports PostgreSQL (production) and SQLite (development/fallback).
"""
import uuid
from datetime import datetime, timezone
from enum import Enum as PyEnum

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    JSON,
)
from sqlalchemy.orm import relationship, declarative_base

Base = declarative_base()


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    # Timezone-aware UTC — replaces deprecated datetime.utcnow() (Py 3.12+).
    return datetime.now(timezone.utc)


# ── Enumerations ──────────────────────────────────────────────────────────────

class ScanStatus(str, PyEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SeverityLevel(str, PyEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ReportFormat(str, PyEnum):
    PDF = "pdf"
    JSON = "json"
    CSV = "csv"


# ── Models ────────────────────────────────────────────────────────────────────

class User(Base):
    """System user (analyst / operator)."""
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=_uuid)
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(128), unique=True, nullable=False)
    hashed_password = Column(String(256), nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=_now)
    updated_at = Column(DateTime, default=_now, onupdate=_now)

    scans = relationship("Scan", back_populates="user", lazy="dynamic")
    __table_args__ = (Index("ix_users_email", "email"),)


class Target(Base):
    """A host / URL that has been registered for scanning."""
    __tablename__ = "targets"

    id = Column(String(36), primary_key=True, default=_uuid)
    address = Column(String(256), nullable=False, unique=True)  # IP, hostname, or URL
    description = Column(String(512), nullable=True)
    resolved_ip = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=_now)
    last_scanned_at = Column(DateTime, nullable=True)
    # Continuous monitoring: when True, the RescanScheduler will re-scan this
    # target every RESCAN_INTERVAL_MINUTES. Default True so every newly added
    # target is monitored automatically; operator can opt-out per target.
    auto_rescan = Column(Boolean, default=True, nullable=False)

    scans = relationship("Scan", back_populates="target", lazy="dynamic")
    __table_args__ = (Index("ix_targets_address", "address", unique=True),)


class Scan(Base):
    """A single scanning session against one target."""
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=_uuid)
    target_id = Column(String(36), ForeignKey("targets.id"), nullable=False)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True)

    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False)
    scan_type = Column(String(64), default="full")           # full | quick | stealth
    port_range = Column(String(64), default="1-1024")
    adaptive_mode = Column(Boolean, default=False)

    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, nullable=True)

    raw_results = Column(JSON, nullable=True)                # store raw nmap / scapy output
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=_now)

    target = relationship("Target", back_populates="scans")
    user = relationship("User", back_populates="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", lazy="dynamic")
    reports = relationship("Report", back_populates="scan", lazy="dynamic")

    __table_args__ = (
        Index("ix_scans_target_id", "target_id"),
        Index("ix_scans_status", "status"),
        Index("ix_scans_created_at", "created_at"),
    )


class Vulnerability(Base):
    """A vulnerability finding produced during a scan."""
    __tablename__ = "vulnerabilities"

    id = Column(String(36), primary_key=True, default=_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)

    name = Column(String(256), nullable=False)
    vuln_type = Column(String(128), nullable=False)          # e.g. "SQL Injection"
    severity = Column(Enum(SeverityLevel), nullable=False)
    cvss_score = Column(Float, nullable=True)

    # Explainable AI fields
    explanation = Column(Text, nullable=True)
    technical_description = Column(Text, nullable=True)
    impact = Column(Text, nullable=True)
    fix = Column(JSON, nullable=True)                        # list of remediation steps
    owasp_mapping = Column(String(128), nullable=True)
    cve_references = Column(JSON, nullable=True)             # list of CVE IDs

    # Evidence
    affected_url = Column(String(512), nullable=True)
    affected_port = Column(Integer, nullable=True)
    payload_used = Column(Text, nullable=True)
    response_snippet = Column(Text, nullable=True)

    is_false_positive = Column(Boolean, default=False)
    created_at = Column(DateTime, default=_now)

    scan = relationship("Scan", back_populates="vulnerabilities")

    __table_args__ = (
        Index("ix_vulns_scan_id", "scan_id"),
        Index("ix_vulns_severity", "severity"),
    )


class Report(Base):
    """Generated report artifact for a completed scan."""
    __tablename__ = "reports"

    id = Column(String(36), primary_key=True, default=_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)

    format = Column(Enum(ReportFormat), nullable=False)
    file_path = Column(String(512), nullable=False)
    file_size_bytes = Column(Integer, nullable=True)
    generated_at = Column(DateTime, default=_now)

    scan = relationship("Scan", back_populates="reports")
    __table_args__ = (Index("ix_reports_scan_id", "scan_id"),)
