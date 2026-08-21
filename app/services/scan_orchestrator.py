from sqlalchemy.orm import Session
import datetime

from ..models import ScanJob, Violation, SecurityFinding
from ..database import SessionLocal
from ..websocket_manager import manager
from .accessibility_service import run_accessibility_scan, calculate_accessibility_score
from .security_service import run_security_scan, calculate_security_score


async def run_full_scan(job_id: str, url: str):
    """
    Runs both scan engines for a single job, updating status + pushing
    WebSocket progress at each stage. Runs as a FastAPI background task,
    so this executes after the /scan endpoint has already responded.
    """
    db: Session = SessionLocal()
    try:
        job = db.query(ScanJob).filter(ScanJob.id == job_id).first()

        await _update_status(db, job, "loading_page", "Launching browser and loading page...")

        try:
            a11y_result = await run_accessibility_scan(url)
        except Exception as e:
            await _fail(db, job, f"Accessibility scan failed: {e}")
            return

        await _update_status(db, job, "running_checks", "Running accessibility and security checks...")

        try:
            security_findings = await run_security_scan(url, a11y_result["mixed_content"])
        except Exception as e:
            security_findings = []  # don't fail the whole job if only security checks error out

        await _update_status(db, job, "processing_results", "Calculating scores and saving results...")

        violations = a11y_result["violations"]
        for v in violations:
            db.add(Violation(
                job_id=job_id,
                rule_id=v.get("id", "unknown"),
                impact=v.get("impact", "minor"),
                description=v.get("description", ""),
                help_text=v.get("help", ""),
                help_url=v.get("helpUrl", ""),
                node_count=len(v.get("nodes", [])),
                nodes=[{"html": n.get("html"), "target": n.get("target")} for n in v.get("nodes", [])],
            ))

        for f in security_findings:
            db.add(SecurityFinding(
                job_id=job_id,
                check_id=f["check_id"],
                category=f["category"],
                severity=f["severity"],
                title=f["title"],
                description=f["description"],
                passed=1 if f["passed"] else 0,
            ))

        job.accessibility_score = calculate_accessibility_score(violations)
        job.security_score = calculate_security_score(security_findings)
        job.status = "completed"
        job.completed_at = datetime.datetime.utcnow()
        db.commit()

        await manager.send_progress(job_id, "completed", "Scan complete.")

    finally:
        db.close()


async def _update_status(db: Session, job: ScanJob, status: str, message: str):
    job.status = status
    db.commit()
    await manager.send_progress(job.id, status, message)


async def _fail(db: Session, job: ScanJob, message: str):
    job.status = "failed"
    job.error_message = message
    db.commit()
    await manager.send_progress(job.id, "failed", message)
