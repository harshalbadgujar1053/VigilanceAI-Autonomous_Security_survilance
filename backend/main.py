import sys, os

# Fix import paths
sys.path.insert(0, '/home/kali/vigilance-ai')
sys.path.insert(0, '/home/kali/vigilance-ai/agent')
sys.path.insert(0, '/home/kali/vigilance-ai/backend')

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.orm import Session

from database import SessionLocal, init_db, AlertRecord, ClassificationRecord, ReportRecord

# Init DB on startup
init_db()

# Import agent modules
from agent.classify_alert import classify_alert
from agent.alert_schema import SAMPLE_ALERTS, NormalizedAlert

app = FastAPI(title="Vigilance AI", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://192.168.43.137:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# DB Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Pydantic schemas
class ClassifyRequest(BaseModel):
    alert: dict

class ReportRequest(BaseModel):
    alert: dict
    classification: Optional[dict] = None

class SaveReportRequest(BaseModel):
    alert_id: str
    severity: str
    agent_name: str
    report_text: str

class SaveClassificationRequest(BaseModel):
    alert_id: str
    severity: str
    reasoning: str
    mitre_tactics: Optional[str] = ""

# ──────────────────────────────────────────
# ORIGINAL ENDPOINTS
# ──────────────────────────────────────────

@app.get("/")
def root():
    return {"status": "online", "service": "Vigilance AI Backend", "version": "1.0.0"}

@app.post("/classify")
async def classify(request: ClassifyRequest):
    try:
        result = classify_alert(request.alert)
        return {"success": True, "classification": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/report")
async def generate_report_endpoint(request: ReportRequest):
    try:
        from agent.tools.generate_report import generate_report as gen_report
        findings = f"""Alert: {request.alert}\nClassification: {request.classification or {}}"""
        report = gen_report.invoke(findings)
        return {"success": True, "report": report}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/classify/sample/{name}")
async def classify_sample(name: str):
    if name not in SAMPLE_ALERTS:
        raise HTTPException(status_code=404, detail=f"Sample '{name}' not found")
    try:
        result = classify_alert(SAMPLE_ALERTS[name])
        return {"success": True, "alert": SAMPLE_ALERTS[name], "classification": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ──────────────────────────────────────────
# NEW DATABASE ENDPOINTS
# ──────────────────────────────────────────

@app.get("/alerts")
def get_alerts(db: Session = Depends(get_db)):
    alerts = db.query(AlertRecord).order_by(AlertRecord.created_at.desc()).all()
    return {"success": True, "count": len(alerts), "alerts": [
        {
            "id": a.id,
            "timestamp": a.timestamp,
            "rule_id": a.rule_id,
            "rule_level": a.rule_level,
            "description": a.description,
            "agent_name": a.agent_name,
            "agent_ip": a.agent_ip,
            "severity": a.severity,
            "raw_data": a.raw_data,
            "created_at": str(a.created_at)
        } for a in alerts
    ]}

@app.post("/alerts/save")
def save_alert(alert: dict, db: Session = Depends(get_db)):
    existing = db.query(AlertRecord).filter(AlertRecord.id == alert.get("id")).first()
    if existing:
        return {"success": True, "message": "Alert already exists", "id": existing.id}
    record = AlertRecord(
        id=alert.get("id", ""),
        timestamp=alert.get("timestamp", ""),
        rule_id=str(alert.get("rule", {}).get("id", "")),
        rule_level=alert.get("rule", {}).get("level", 0),
        description=alert.get("rule", {}).get("description", ""),
        agent_name=alert.get("agent", {}).get("name", ""),
        agent_ip=alert.get("agent", {}).get("ip", ""),
        severity=alert.get("severity", "UNKNOWN"),
        raw_data=alert
    )
    db.add(record)
    db.commit()
    return {"success": True, "message": "Alert saved", "id": record.id}

@app.post("/classifications/save")
def save_classification(req: SaveClassificationRequest, db: Session = Depends(get_db)):
    record = ClassificationRecord(
        alert_id=req.alert_id,
        severity=req.severity,
        reasoning=req.reasoning,
        mitre_tactics=req.mitre_tactics
    )
    db.add(record)
    db.commit()
    return {"success": True, "message": "Classification saved", "id": record.id}

@app.post("/reports/save")
def save_report(req: SaveReportRequest, db: Session = Depends(get_db)):
    record = ReportRecord(
        alert_id=req.alert_id,
        severity=req.severity,
        agent_name=req.agent_name,
        report_text=req.report_text
    )
    db.add(record)
    db.commit()
    return {"success": True, "message": "Report saved", "id": record.id}

@app.get("/reports")
def get_reports(db: Session = Depends(get_db)):
    reports = db.query(ReportRecord).order_by(ReportRecord.created_at.desc()).all()
    return {"success": True, "count": len(reports), "reports": [
        {
            "id": r.id,
            "alert_id": r.alert_id,
            "severity": r.severity,
            "agent_name": r.agent_name,
            "report_preview": r.report_text[:200] + "..." if len(r.report_text) > 200 else r.report_text,
            "created_at": str(r.created_at)
        } for r in reports
    ]}

@app.get("/reports/{report_id}")
def get_report_by_id(report_id: int, db: Session = Depends(get_db)):
    report = db.query(ReportRecord).filter(ReportRecord.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return {
        "success": True,
        "report": {
            "id": report.id,
            "alert_id": report.alert_id,
            "severity": report.severity,
            "agent_name": report.agent_name,
            "report_text": report.report_text,
            "created_at": str(report.created_at)
        }
    }
