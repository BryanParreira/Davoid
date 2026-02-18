from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime
import os

Base = declarative_base()
DB_PATH = "davoid_mission.db"

class ScanResult(Base):
    __tablename__ = 'mission_logs'
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    module = Column(String)
    target = Column(String)
    data = Column(Text)
    severity = Column(String)  # INFO, HIGH, CRITICAL

class Database:
    def __init__(self):
        # Create database if it doesn't exist
        self.engine = create_engine(f'sqlite:///{DB_PATH}')
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

    def log(self, module, target, data, severity="INFO"):
        """Saves a finding to the mission database."""
        session = self.Session()
        try:
            entry = ScanResult(
                module=module, 
                target=target, 
                data=str(data), 
                severity=severity
            )
            session.add(entry)
            session.commit()
        except Exception as e:
            print(f"[!] DB Error: {e}")
        finally:
            session.close()

    def get_all(self):
        """Retrieves all mission logs for reporting."""
        session = self.Session()
        try:
            results = session.query(ScanResult).order_by(ScanResult.timestamp.desc()).all()
            return results
        finally:
            session.close()

# Global DB Instance
db = Database()