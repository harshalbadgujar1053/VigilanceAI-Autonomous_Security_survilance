from sqlalchemy import create_engine, Column, String, Integer, Text, DateTime, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

DATABASE_URL = "postgresql://vigilance:vigilance123@localhost:5432/vigilancedb"

engine = create_engine(DATABASE_URL)
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
    classified_at  = Column(DateTime, default=datetime.utcnow)

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
