import uuid
import datetime
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, JSON, Float
from sqlalchemy.orm import relationship
from .database import Base


def gen_id():
    return str(uuid.uuid4())


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(String, primary_key=True, default=gen_id)
    url = Column(String, nullable=False)
    status = Column(String, default="queued")  # queued, loading_page, running_checks, processing_results, completed, failed
    error_message = Column(String, nullable=True)

    accessibility_score = Column(Integer, nullable=True)
    security_score = Column(Integer, nullable=True)

    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    violations = relationship("Violation", back_populates="job", cascade="all, delete-orphan")
    security_findings = relationship("SecurityFinding", back_populates="job", cascade="all, delete-orphan")


class Violation(Base):
    __tablename__ = "violations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String, ForeignKey("scan_jobs.id"))

    rule_id = Column(String)
    impact = Column(String)  # critical, serious, moderate, minor
    description = Column(String)
    help_text = Column(String)
    help_url = Column(String)
    node_count = Column(Integer, default=0)
    nodes = Column(JSON)  # list of {html, target}

    job = relationship("ScanJob", back_populates="violations")


class SecurityFinding(Base):
    __tablename__ = "security_findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String, ForeignKey("scan_jobs.id"))

    check_id = Column(String)       # e.g. "csp-header", "hsts-header", "tls-version"
    category = Column(String)       # headers, cookies, tls, mixed_content, info_disclosure, exposed_paths
    severity = Column(String)       # high, medium, low, info
    title = Column(String)
    description = Column(String)
    passed = Column(Integer)        # 1 = passed, 0 = failed

    job = relationship("ScanJob", back_populates="security_findings")
