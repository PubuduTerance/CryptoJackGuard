from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import Column, DateTime, Float, Integer, JSON, String
from src.backend.database import Base


class User(Base):
    """User account model for authentication and access control."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(50), default="admin", nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class AlertRecord(Base):
    """Centralized security alert record received from CryptoJackGuard endpoints."""
    __tablename__ = "alert_records"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    timestamp = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    process_name = Column(String(255), index=True, nullable=True)
    pid = Column(Integer, nullable=True)
    risk_score = Column(Float, nullable=False, default=0.0)
    ml_confidence = Column(Float, nullable=True, default=0.0)
    action_taken = Column(String(255), nullable=True)
    details = Column(JSON, nullable=True)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "process_name": self.process_name,
            "pid": self.pid,
            "risk_score": self.risk_score,
            "ml_confidence": self.ml_confidence,
            "action_taken": self.action_taken,
            "details": self.details or {},
        }
