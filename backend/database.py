from sqlalchemy import create_engine, Column, String, Integer, Text, DateTime, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import os

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://vigilance:vigilance123@localhost:5432/vigilancedb"
)

engine = create_engine(DATABASE_URL, pool_pre_ping=True, pool_recycle=1800)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- Tables ---

class AlertRecord(Base):
    __tablename__ = "alerts"
    id          = Column(String, primary_key=True)
    timestamp   = Column(String)
    rule_id     = Column(String)
    rule_level  = Column(Integer)
    description = Column(String)
    agent_name  = Column(String)
    agent_ip    = Column(String)
    severity    = Column(String)          # filled after classification
    raw_data    = Column(JSON)            # full original alert JSON
    created_at  = Column(DateTime, default=datetime.utcnow)

class ClassificationRecord(Base):
    __tablename__ = "classifications"
    id             = Column(Integer, primary_key=True, autoincrement=True)
    alert_id       = Column(String)
    severity       = Column(String)
    reasoning      = Column(Text)
    mitre_tactics  = Column(Text)
    recommended_actions = Column(Text)
    verdict        = Column(String, nullable=True)
    confidence     = Column(String, nullable=True)
    classified_at  = Column(DateTime, default=datetime.utcnow)

class ClassificationQueue(Base):
    __tablename__ = "classification_queue"
    id           = Column(Integer, primary_key=True, autoincrement=True)
    alert_id     = Column(String, nullable=False)
    status       = Column(String, default="pending")  # pending | processing | done | failed
    attempts     = Column(Integer, default=0)
    enqueued_at  = Column(DateTime, default=datetime.utcnow)
    updated_at   = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    error        = Column(Text, nullable=True)

class ReportRecord(Base):
    __tablename__ = "reports"
    id           = Column(Integer, primary_key=True, autoincrement=True)
    alert_id     = Column(String)
    severity     = Column(String)
    agent_name   = Column(String)
    report_text  = Column(Text)
    created_at   = Column(DateTime, default=datetime.utcnow)

def init_db():
    Base.metadata.create_all(bind=engine)
    print("✅ All tables created successfully.")

if __name__ == "__main__":
    init_db()
