from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime
from cryptography.fernet import Fernet
import os

Base = declarative_base()
DB_PATH = "davoid_mission.db"
# Store the key in the root of the davoid install directory
KEY_PATH = "/opt/davoid/.db_key"


class ScanResult(Base):
    __tablename__ = 'mission_logs'
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    module = Column(String)
    target = Column(String)
    data = Column(Text)  # Now storing ENCRYPTED data
    severity = Column(String)  # INFO, HIGH, CRITICAL


class Database:
    def __init__(self):
        self._init_crypto()
        # Create database if it doesn't exist
        self.engine = create_engine(f'sqlite:///{DB_PATH}')
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

    def _init_crypto(self):
        """Generates or loads the master DB encryption key."""
        if not os.path.exists(KEY_PATH):
            key = Fernet.generate_key()
            with open(KEY_PATH, 'wb') as f:
                f.write(key)
            try:
                # Ensure only root/owner can read this
                os.chmod(KEY_PATH, 0o600)
            except:
                pass
        with open(KEY_PATH, 'rb') as f:
            self.cipher = Fernet(f.read())

    def log(self, module, target, data, severity="INFO"):
        """Saves a finding to the mission database, encrypting the data payload."""
        session = self.Session()
        try:
            encrypted_data = self.cipher.encrypt(str(data).encode()).decode()

            entry = ScanResult(
                module=module,
                target=target,
                data=encrypted_data,
                severity=severity
            )
            session.add(entry)
            session.commit()
        except Exception as e:
            print(f"[!] DB Error: {e}")
        finally:
            session.close()

    def get_all(self):
        """Retrieves and decrypts all mission logs for reporting."""
        session = self.Session()
        try:
            results = session.query(ScanResult).order_by(
                ScanResult.timestamp.desc()).all()
            for r in results:
                try:
                    r.data = self.cipher.decrypt(r.data.encode()).decode()
                except Exception:
                    r.data = "[DECRYPTION FAILED - DATA CORRUPT OR KEY MISMATCH]"
            return results
        finally:
            session.close()


# Global DB Instance
db = Database()
