from datetime import datetime, timezone
import unittest
from unittest.mock import MagicMock, patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.backend.auth import (
    create_access_token,
    hash_password,
    verify_password,
    verify_token,
)
from src.backend.database import Base
from src.backend.models import AlertRecord, User


class TestBackendAuth(unittest.TestCase):
    def test_password_hashing_and_verification(self):
        plain = "securepassword123"
        hashed = hash_password(plain)
        self.assertNotEqual(plain, hashed)
        self.assertTrue(verify_password(plain, hashed))
        self.assertFalse(verify_password("wrongpassword", hashed))

    def test_jwt_token_creation_and_verification(self):
        payload = {"sub": "admin", "role": "admin"}
        token = create_access_token(payload)
        self.assertIsInstance(token, str)

        decoded = verify_token(token)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded["sub"], "admin")
        self.assertEqual(decoded["role"], "admin")
        self.assertIn("exp", decoded)

    def test_invalid_jwt_token_returns_none(self):
        self.assertIsNone(verify_token("invalid.token.payload"))


class TestBackendModels(unittest.TestCase):
    def setUp(self):
        # Use an in-memory SQLite DB for isolated model unit testing
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self.db = self.Session()

    def tearDown(self):
        self.db.close()
        Base.metadata.drop_all(bind=self.engine)

    def test_user_model_crud(self):
        user = User(
            username="analyst1",
            hashed_password=hash_password("analystPass123"),
            role="analyst",
        )
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)

        self.assertIsNotNone(user.id)
        self.assertEqual(user.username, "analyst1")
        self.assertEqual(user.role, "analyst")

        d = user.to_dict()
        self.assertEqual(d["username"], "analyst1")
        self.assertEqual(d["role"], "analyst")

    def test_alert_record_model_crud(self):
        record = AlertRecord(
            timestamp=datetime.now(timezone.utc),
            process_name="xmrig.exe",
            pid=4321,
            risk_score=92.5,
            ml_confidence=0.95,
            action_taken="Terminated",
            details={"reasons": ["High CPU", "Stratum network connection"]},
        )
        self.db.add(record)
        self.db.commit()
        self.db.refresh(record)

        self.assertIsNotNone(record.id)
        self.assertEqual(record.process_name, "xmrig.exe")
        self.assertEqual(record.risk_score, 92.5)

        d = record.to_dict()
        self.assertEqual(d["process_name"], "xmrig.exe")
        self.assertEqual(d["pid"], 4321)
        self.assertEqual(d["action_taken"], "Terminated")
        self.assertIn("reasons", d["details"])


class TestReportGenerator(unittest.TestCase):
    def test_generate_security_report(self):
        import os
        import tempfile
        from src.backend.report_generator import generate_security_report

        alerts = [
            {
                "timestamp": "2026-08-26T04:00:00Z",
                "process_name": "xmrig.exe",
                "pid": 5432,
                "risk_score": 90.0,
                "action_taken": "Terminated",
                "details": {"reasons": ["Mining IOC detected", "High CPU"]},
            },
            {
                "timestamp": "2026-08-26T04:01:00Z",
                "process_name": "chrome.exe",
                "pid": 1111,
                "risk_score": 10.0,
                "action_taken": "alert",
                "details": {"reasons": []},
            },
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            out_pdf = os.path.join(tmpdir, "test_sec_report.pdf")
            result_path = generate_security_report(alerts, output_path=out_pdf)
            self.assertTrue(os.path.exists(result_path))
            self.assertGreater(os.path.getsize(result_path), 500)

    def test_generate_security_report_bytes(self):
        from src.backend.report_generator import generate_security_report

        alerts = [
            {
                "timestamp": "2026-08-26T04:00:00Z",
                "process_name": "xmrig.exe",
                "pid": 5432,
                "risk_score": 90.0,
                "action_taken": "Terminated",
                "details": {"reasons": ["Mining IOC detected", "High CPU"]},
            }
        ]
        pdf_bytes = generate_security_report(
            alerts,
            output_path=None,
            system_metrics={"cpu_percent": 75.5, "memory_percent": 42.0},
        )
        self.assertIsInstance(pdf_bytes, bytes)
        self.assertGreater(len(pdf_bytes), 500)
        self.assertTrue(pdf_bytes.startswith(b"%PDF-"))


if __name__ == "__main__":
    unittest.main()
