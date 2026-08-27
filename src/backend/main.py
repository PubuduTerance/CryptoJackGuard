from __future__ import annotations
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import os
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional

import tempfile

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from src.backend.auth import (
    create_access_token,
    get_current_user,
    hash_password,
    verify_password,
)
from src.backend.database import Base, engine, get_db
from src.backend.models import AlertRecord, User
from src.privacy.redaction import redact_command_line


# ---------------------------------------------------------------------------
# Pydantic Schemas
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str = Field(..., example="admin")
    password: str = Field(..., example="securepassword123")


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    role: str


class AlertCreateRequest(BaseModel):
    process_name: Optional[str] = None
    name: Optional[str] = None
    pid: Optional[int] = None
    risk_score: Optional[float] = None
    score: Optional[float] = None
    ml_confidence: Optional[float] = None
    action_taken: Optional[str] = None
    response_action: Optional[str] = None
    timestamp: Optional[str] = None
    cmdline: Optional[str] = None
    reasons: Optional[List[str]] = None
    details: Optional[Dict[str, Any]] = None


class StatusResponse(BaseModel):
    status: str
    service: str
    database_connected: bool
    timestamp: str
    version: str


# ---------------------------------------------------------------------------
# Lifespan Management (DB Init & Default Admin Seed)
# ---------------------------------------------------------------------------

def init_db_and_seed() -> None:
    """Initialize database tables and seed default admin credentials."""
    try:
        # Create all tables in PostgreSQL
        Base.metadata.create_all(bind=engine)
        print("[+] PostgreSQL database tables verified/created successfully.")

        # Seed default admin user
        from src.backend.database import SessionLocal
        db = SessionLocal()
        try:
            admin_user = db.query(User).filter(User.username == "admin").first()
            if not admin_user:
                hashed = hash_password("securepassword123")
                new_admin = User(
                    username="admin",
                    hashed_password=hashed,
                    role="admin",
                )
                db.add(new_admin)
                db.commit()
                print("[+] Default admin user ('admin') seeded successfully.")
            else:
                print("[*] Admin user already exists in database.")
        finally:
            db.close()
    except Exception as exc:
        print(f"[!] Database initialization warning: {exc}", file=sys.stderr)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    init_db_and_seed()
    yield
    # Shutdown


# ---------------------------------------------------------------------------
# FastAPI Application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="CryptoJackGuard Cloud Central API",
    description="Centralized telemetry, alert ingestion, and administration backend for CryptoJackGuard.",
    version="2.0.0",
    lifespan=lifespan,
)

# Enable CORS for web dashboards and telemetry clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/", tags=["Health"])
def root():
    return {
        "message": "CryptoJackGuard Central API is running.",
        "docs_url": "/docs",
        "status_url": "/api/status",
    }


@app.get("/api/status", response_model=StatusResponse, tags=["Health"])
def get_status(db: Session = Depends(get_db)):
    """Health check endpoint confirming API status and database connectivity."""
    db_ok = False
    try:
        db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False

    return StatusResponse(
        status="online" if db_ok else "degraded",
        service="CryptoJackGuard Cloud API",
        database_connected=db_ok,
        timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        version="2.0.0",
    )


@app.post("/api/login", response_model=LoginResponse, tags=["Authentication"])
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    """Authenticate administrator or user and generate JWT bearer access token."""
    user = db.query(User).filter(User.username == payload.username).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(data={"sub": user.username, "role": user.role})
    return LoginResponse(
        access_token=token,
        token_type="bearer",
        username=user.username,
        role=user.role,
    )


@app.post("/api/alerts", status_code=status.HTTP_201_CREATED, tags=["Telemetry"])
def ingest_alert(alert_in: AlertCreateRequest, db: Session = Depends(get_db)):
    """Ingest a security alert or response action from a local CryptoJackGuard monitor."""
    # Resolve process name & PID
    proc_name = alert_in.process_name or alert_in.name or "unknown"
    pid = alert_in.pid

    # Resolve risk score and action taken
    risk = float(alert_in.risk_score if alert_in.risk_score is not None else (alert_in.score or 0.0))
    action = alert_in.action_taken or alert_in.response_action

    # Prepare structured details dictionary
    details_dict = alert_in.details.copy() if alert_in.details else {}
    if alert_in.cmdline:
        details_dict["cmdline"] = redact_command_line(alert_in.cmdline)
    if alert_in.reasons:
        details_dict["reasons"] = alert_in.reasons

    # Parse or create timestamp
    if alert_in.timestamp:
        try:
            ts = datetime.fromisoformat(alert_in.timestamp.replace("Z", "+00:00"))
        except Exception:
            ts = datetime.now(timezone.utc)
    else:
        ts = datetime.now(timezone.utc)

    # Instantiate and persist AlertRecord
    record = AlertRecord(
        timestamp=ts,
        process_name=proc_name,
        pid=pid,
        risk_score=risk,
        ml_confidence=alert_in.ml_confidence,
        action_taken=action,
        details=details_dict,
    )

    db.add(record)
    db.commit()
    db.refresh(record)

    return {
        "status": "success",
        "message": "Alert record stored successfully",
        "alert_id": record.id,
        "record": record.to_dict(),
    }


@app.get("/api/alerts", tags=["Telemetry"])
def list_alerts(
    limit: int = 50,
    offset: int = 0,
    min_score: float = 0.0,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve historical security alerts (Protected endpoint, requires JWT token)."""
    query = db.query(AlertRecord).filter(AlertRecord.risk_score >= min_score)
    total_count = query.count()
    alerts = query.order_by(AlertRecord.timestamp.desc()).offset(offset).limit(limit).all()

    return {
        "total": total_count,
        "limit": limit,
        "offset": offset,
        "alerts": [a.to_dict() for a in alerts],
    }


@app.get("/api/reports/pdf", tags=["Reports"])
def download_pdf_report(
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Generate and download an enterprise PDF security intelligence report (Protected endpoint)."""
    from src.backend.report_generator import generate_security_report

    alerts = db.query(AlertRecord).order_by(AlertRecord.timestamp.desc()).limit(limit).all()

    # Create temporary PDF file
    temp_pdf = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
    temp_pdf.close()

    generate_security_report(alerts, output_path=temp_pdf.name)

    return FileResponse(
        path=temp_pdf.name,
        media_type="application/pdf",
        filename=f"CryptoJackGuard_Security_Report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.pdf",
    )


if __name__ == "__main__":

    import uvicorn
    uvicorn.run("src.backend.main:app", host="0.0.0.0", port=8000, reload=True)
