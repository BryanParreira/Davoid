"""
core/database.py — Mission Database Engine
FIXES:
  - get_all() now returns plain dicts (no more detached SQLAlchemy instance errors)
  - Column renamed alias: callers expecting 'details' now work correctly
  - Added get_critical_logs() so ai_assist.py Strategy 1 works
  - Added search() and clear() utility methods
  - Graceful handling of corrupt/missing encryption key
  - Thread-safe session handling (one session per call, never shared)
"""

import os
import threading
from datetime import datetime

from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, desc
from sqlalchemy.orm import declarative_base, sessionmaker
from cryptography.fernet import Fernet, InvalidToken

Base = declarative_base()

# ─────────────────────────────────────────────────────────────────────────────
#  PATHS
# ─────────────────────────────────────────────────────────────────────────────

USER_HOME  = os.path.expanduser("~")
STATE_DIR  = os.path.join(USER_HOME, ".davoid")
DB_PATH    = os.path.join(STATE_DIR, "davoid_mission.db")
KEY_PATH   = os.path.join(STATE_DIR, ".db_key")

os.makedirs(STATE_DIR, exist_ok=True)


# ─────────────────────────────────────────────────────────────────────────────
#  ORM MODEL
# ─────────────────────────────────────────────────────────────────────────────

class ScanResult(Base):
    __tablename__ = "mission_logs"

    id        = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    module    = Column(String,   nullable=False, default="")
    target    = Column(String,   nullable=False, default="")
    data      = Column(Text,     nullable=False, default="")   # stores ENCRYPTED payload
    severity  = Column(String,   nullable=False, default="INFO")


# ─────────────────────────────────────────────────────────────────────────────
#  DATABASE CLASS
# ─────────────────────────────────────────────────────────────────────────────

class Database:
    """
    Thread-safe, encrypted SQLite mission database.

    All public methods return plain Python dicts with these keys:
        id, timestamp, module, target, severity, details

    The 'details' key is an alias for the underlying 'data' column so that
    every caller (reporter, ai_assist, purple_team, etc.) works without
    needing to know about the internal column name.
    """

    def __init__(self):
        self._lock   = threading.Lock()
        self._cipher = None
        self._init_crypto()

        self.engine  = create_engine(
            f"sqlite:///{DB_PATH}",
            connect_args={"check_same_thread": False},
        )
        Base.metadata.create_all(self.engine)
        self._Session = sessionmaker(bind=self.engine)

    # ── Crypto ────────────────────────────────────────────────────

    def _init_crypto(self):
        """Load or generate the Fernet encryption key."""
        try:
            if not os.path.exists(KEY_PATH):
                key = Fernet.generate_key()
                with open(KEY_PATH, "wb") as f:
                    f.write(key)
                try:
                    os.chmod(KEY_PATH, 0o600)
                except OSError:
                    pass

            with open(KEY_PATH, "rb") as f:
                raw_key = f.read().strip()

            self._cipher = Fernet(raw_key)

        except Exception as e:
            print(f"[!] DB crypto init error: {e}. Logs will be stored in plaintext.")
            self._cipher = None

    def _encrypt(self, text: str) -> str:
        if self._cipher:
            return self._cipher.encrypt(text.encode()).decode()
        return text

    def _decrypt(self, text: str) -> str:
        if not self._cipher:
            return text
        try:
            return self._cipher.decrypt(text.encode()).decode()
        except (InvalidToken, Exception):
            return "[DECRYPTION FAILED — data corrupt or key mismatch]"

    # ── Session helper ────────────────────────────────────────────

    def _make_session(self):
        """Always create a fresh session; callers must close it."""
        return self._Session()

    # ── Row → dict ────────────────────────────────────────────────

    def _row_to_dict(self, row: ScanResult, decrypt: bool = True) -> dict:
        """
        Convert an ORM row to a plain dict.
        Always decrypts and always exposes 'details' as an alias for 'data'.
        Session can be safely closed after this call.
        """
        raw_data = row.data or ""
        details  = self._decrypt(raw_data) if decrypt else raw_data

        return {
            "id":        row.id,
            "timestamp": str(row.timestamp) if row.timestamp else "",
            "module":    row.module   or "",
            "target":    row.target   or "",
            "severity":  row.severity or "INFO",
            "details":   details,          # ← the alias every caller expects
            "data":      details,          # ← keep 'data' too for completeness
        }

    # ── Public API ────────────────────────────────────────────────

    def log(self, module: str, target: str, data: str, severity: str = "INFO") -> bool:
        """
        Write a finding to the database.
        Returns True on success, False on failure.
        """
        session = self._make_session()
        try:
            entry = ScanResult(
                module    = str(module),
                target    = str(target),
                data      = self._encrypt(str(data)),
                severity  = str(severity).upper(),
                timestamp = datetime.utcnow(),
            )
            session.add(entry)
            session.commit()
            return True
        except Exception as e:
            session.rollback()
            print(f"[!] DB log error: {e}")
            return False
        finally:
            session.close()

    def get_all(self) -> list[dict]:
        """
        Return all log entries as plain dicts, newest first.
        Safe to use after the session is closed.
        """
        session = self._make_session()
        try:
            rows = (
                session.query(ScanResult)
                .order_by(desc(ScanResult.timestamp))
                .all()
            )
            return [self._row_to_dict(r) for r in rows]
        except Exception as e:
            print(f"[!] DB get_all error: {e}")
            return []
        finally:
            session.close()

    def get_critical_logs(self, limit: int = 10) -> list[dict]:
        """
        Return the most recent HIGH and CRITICAL entries.
        Used by ai_assist.py Strategy 1 path.
        """
        session = self._make_session()
        try:
            rows = (
                session.query(ScanResult)
                .filter(ScanResult.severity.in_(["HIGH", "CRITICAL"]))
                .order_by(desc(ScanResult.timestamp))
                .limit(limit)
                .all()
            )
            return [self._row_to_dict(r) for r in rows]
        except Exception as e:
            print(f"[!] DB get_critical_logs error: {e}")
            return []
        finally:
            session.close()

    def search(self, module: str = None, target: str = None,
               severity: str = None, limit: int = 100) -> list[dict]:
        """
        Flexible search with optional filters.
        All parameters are optional; pass None to skip that filter.
        """
        session = self._make_session()
        try:
            q = session.query(ScanResult)
            if module:
                q = q.filter(ScanResult.module.ilike(f"%{module}%"))
            if target:
                q = q.filter(ScanResult.target.ilike(f"%{target}%"))
            if severity:
                q = q.filter(ScanResult.severity == severity.upper())
            rows = q.order_by(desc(ScanResult.timestamp)).limit(limit).all()
            return [self._row_to_dict(r) for r in rows]
        except Exception as e:
            print(f"[!] DB search error: {e}")
            return []
        finally:
            session.close()

    def get_stats(self) -> dict:
        """
        Return a summary dict: total entries and counts per severity.
        Useful for the header/dashboard.
        """
        session = self._make_session()
        try:
            total    = session.query(ScanResult).count()
            critical = session.query(ScanResult).filter_by(severity="CRITICAL").count()
            high     = session.query(ScanResult).filter_by(severity="HIGH").count()
            info     = session.query(ScanResult).filter_by(severity="INFO").count()
            return {
                "total":    total,
                "critical": critical,
                "high":     high,
                "info":     info,
            }
        except Exception as e:
            print(f"[!] DB stats error: {e}")
            return {"total": 0, "critical": 0, "high": 0, "info": 0}
        finally:
            session.close()

    def clear(self) -> bool:
        """
        Delete all log entries. Used by the vanish protocol.
        Returns True on success.
        """
        session = self._make_session()
        try:
            session.query(ScanResult).delete()
            session.commit()
            return True
        except Exception as e:
            session.rollback()
            print(f"[!] DB clear error: {e}")
            return False
        finally:
            session.close()

    def count(self) -> int:
        """Return total number of log entries."""
        session = self._make_session()
        try:
            return session.query(ScanResult).count()
        except Exception:
            return 0
        finally:
            session.close()


# ─────────────────────────────────────────────────────────────────────────────
#  GLOBAL INSTANCE
# ─────────────────────────────────────────────────────────────────────────────

db = Database()