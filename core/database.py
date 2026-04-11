from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime
from cryptography.fernet import Fernet
import os

Base = declarative_base()

# ---------------------------------------------------------
# SECURITY FIX: Store databases and keys in the user's home folder
# so it doesn't violate /opt/davoid root permissions.
# ---------------------------------------------------------
USER_HOME = os.path.expanduser("~")
STATE_DIR = os.path.join(USER_HOME, ".davoid")

# Ensure the state directory exists
os.makedirs(STATE_DIR, exist_ok=True)

DB_PATH  = os.path.join(STATE_DIR, "davoid_mission.db")
KEY_PATH = os.path.join(STATE_DIR, ".db_key")


class ScanResult(Base):
    __tablename__ = 'mission_logs'
    id        = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    module    = Column(String)
    target    = Column(String)
    data      = Column(Text)      # storing ENCRYPTED data
    severity  = Column(String)    # INFO, HIGH, CRITICAL


# ---------------------------------------------------------
# Plain dict wrapper so callers never touch a detached ORM
# object after the session closes (fixes DetachedInstanceError).
# Every public method that returns rows now returns plain dicts.
# ---------------------------------------------------------
class LogRow:
    """Lightweight dict-backed object that mimics ORM attribute access."""
    __slots__ = ("id", "timestamp", "module", "target", "details", "severity")

    def __init__(self, id, timestamp, module, target, details, severity):
        self.id        = id
        self.timestamp = timestamp
        self.module    = module
        self.target    = target
        self.details   = details      # decrypted — callers use .details not .data
        self.severity  = severity

    # Also support dict-style access so existing code using log['key'] works
    def get(self, key, default=""):
        return getattr(self, key, default)

    def __getitem__(self, key):
        return getattr(self, key)

    def __repr__(self):
        return (f"<LogRow id={self.id} module={self.module!r} "
                f"target={self.target!r} severity={self.severity!r}>")


class Database:
    def __init__(self):
        self._init_crypto()
        self.engine  = create_engine(f'sqlite:///{DB_PATH}')
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

    def _init_crypto(self):
        """Generates or loads the master DB encryption key."""
        if not os.path.exists(KEY_PATH):
            key = Fernet.generate_key()
            with open(KEY_PATH, 'wb') as f:
                f.write(key)
            try:
                os.chmod(KEY_PATH, 0o600)
            except Exception:
                pass
        with open(KEY_PATH, 'rb') as f:
            self.cipher = Fernet(f.read())

    # ------------------------------------------------------------------
    def log(self, module, target, data, severity="INFO"):
        """Saves a finding to the mission database, encrypting the data payload."""
        session = self.Session()
        try:
            encrypted_data = self.cipher.encrypt(str(data).encode()).decode()
            entry = ScanResult(
                module=module,
                target=target,
                data=encrypted_data,
                severity=severity,
            )
            session.add(entry)
            session.commit()
        except Exception as e:
            print(f"[!] DB Error: {e}")
            session.rollback()
        finally:
            session.close()

    # ------------------------------------------------------------------
    def get_all(self):
        """
        Retrieves and decrypts all mission logs.
        Returns a list of LogRow objects (safe to use after session closes).
        LogRow supports both attribute access (row.module) and
        dict-style access (row['module'] / row.get('module')).
        """
        session = self.Session()
        try:
            results = session.query(ScanResult).order_by(
                ScanResult.timestamp.desc()).all()

            rows = []
            for r in results:
                try:
                    decrypted = self.cipher.decrypt(r.data.encode()).decode()
                except Exception:
                    decrypted = "[DECRYPTION FAILED - DATA CORRUPT OR KEY MISMATCH]"

                rows.append(LogRow(
                    id        = r.id,
                    timestamp = r.timestamp,
                    module    = r.module,
                    target    = r.target,
                    details   = decrypted,   # note: field is 'details' not 'data'
                    severity  = r.severity,
                ))
            return rows
        finally:
            session.close()

    # ------------------------------------------------------------------
    def get_critical_logs(self, limit=10):
        """
        Returns the most recent HIGH / CRITICAL logs as LogRow objects.
        Used by ai_assist.py — avoids the raw-cursor fallback path.
        """
        session = self.Session()
        try:
            results = (
                session.query(ScanResult)
                .filter(ScanResult.severity.in_(["HIGH", "CRITICAL"]))
                .order_by(ScanResult.timestamp.desc())
                .limit(limit)
                .all()
            )
            rows = []
            for r in results:
                try:
                    decrypted = self.cipher.decrypt(r.data.encode()).decode()
                except Exception:
                    decrypted = "[DECRYPTION FAILED]"

                rows.append(LogRow(
                    id        = r.id,
                    timestamp = r.timestamp,
                    module    = r.module,
                    target    = r.target,
                    details   = decrypted,
                    severity  = r.severity,
                ))
            return rows
        finally:
            session.close()

    # ------------------------------------------------------------------
    def search(self, keyword=None, severity=None, module=None, limit=500):
        """
        Filtered log query — all parameters are optional.
        Returns LogRow list, same as get_all().
        """
        session = self.Session()
        try:
            q = session.query(ScanResult)

            if severity:
                if isinstance(severity, (list, tuple)):
                    q = q.filter(ScanResult.severity.in_(severity))
                else:
                    q = q.filter(ScanResult.severity == severity)

            if module:
                q = q.filter(ScanResult.module == module)

            results = q.order_by(ScanResult.timestamp.desc()).limit(limit).all()

            rows = []
            for r in results:
                try:
                    decrypted = self.cipher.decrypt(r.data.encode()).decode()
                except Exception:
                    decrypted = "[DECRYPTION FAILED]"

                # Apply keyword filter post-decryption (can't do it in SQL on encrypted data)
                if keyword and keyword.lower() not in decrypted.lower() \
                        and keyword.lower() not in (r.target or "").lower():
                    continue

                rows.append(LogRow(
                    id        = r.id,
                    timestamp = r.timestamp,
                    module    = r.module,
                    target    = r.target,
                    details   = decrypted,
                    severity  = r.severity,
                ))
            return rows
        finally:
            session.close()

    # ------------------------------------------------------------------
    def delete_all(self):
        """Wipe the entire mission log (used by Vanish Protocol)."""
        session = self.Session()
        try:
            session.query(ScanResult).delete()
            session.commit()
        except Exception as e:
            print(f"[!] DB wipe error: {e}")
            session.rollback()
        finally:
            session.close()


# Global DB Instance
db = Database()