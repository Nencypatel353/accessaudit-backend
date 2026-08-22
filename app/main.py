from fastapi import FastAPI, Depends, BackgroundTasks, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
import os

from . import models, schemas
from .database import engine, get_db
from .websocket_manager import manager
from .services.scan_orchestrator import run_full_scan

models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="AccessAudit API")

# CORS origins: localhost for local dev, plus your deployed frontend URL
# (set via the FRONTEND_ORIGIN env var on Render)
_extra_origins = os.getenv("FRONTEND_ORIGIN", "")
allowed_origins = ["http://localhost:4200"] + (
    [_extra_origins] if _extra_origins else []
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {"status": "ok", "service": "AccessAudit API"}


@app.post("/scan", response_model=schemas.ScanJobOut)
def create_scan(request: schemas.ScanRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    if not request.url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="URL must start with http:// or https://")

    job = models.ScanJob(url=request.url, status="queued")
    db.add(job)
    db.commit()
    db.refresh(job)

    background_tasks.add_task(run_full_scan, job.id, job.url)

    return job


@app.get("/scan/{job_id}/status", response_model=schemas.ScanJobOut)
def get_scan_status(job_id: str, db: Session = Depends(get_db)):
    job = db.query(models.ScanJob).filter(models.ScanJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return job


@app.get("/scan/{job_id}/results", response_model=schemas.ScanResultsOut)
def get_scan_results(job_id: str, db: Session = Depends(get_db)):
    job = db.query(models.ScanJob).filter(models.ScanJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return {
        "job": job,
        "violations": job.violations,
        "security_findings": job.security_findings,
    }


@app.get("/scans", response_model=list[schemas.ScanJobOut])
def list_scans(db: Session = Depends(get_db)):
    return db.query(models.ScanJob).order_by(models.ScanJob.created_at.desc()).limit(50).all()


@app.websocket("/ws/scan/{job_id}")
async def scan_progress_socket(websocket: WebSocket, job_id: str):
    await manager.connect(job_id, websocket)
    try:
        while True:
            # keep the connection open; client doesn't need to send anything
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(job_id, websocket)
