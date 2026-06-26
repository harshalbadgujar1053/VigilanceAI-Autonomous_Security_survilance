"""
main.py — FastAPI backend (Phase 2)
Project: Vigilance AI
"""

import sys
import os

# Add agent/ folder to path so we can import from it
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "agent"))

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from classify_alert import classify_alert
from alert_schema import NormalizedAlert, SAMPLE_ALERTS

app = FastAPI(
    title="Vigilance AI - Agent API",
    description="SOC co-pilot: alert classification via local Mistral",
    version="0.1.0"
)

# ── Response shape ──────────────────────────────────────
class ClassificationResponse(BaseModel):
    alert_id: str
    classification: str

# ── 1. Health check ─────────────────────────────────────
@app.get("/")
def health_check():
    return {"status": "Vigilance AI agent API is running"}

# ── 2. Classify a real alert (POST) ─────────────────────
@app.post("/classify", response_model=ClassificationResponse)
def classify(alert: NormalizedAlert):
    """
    POST a Wazuh alert JSON → get SEVERITY + REASONING back.
    FastAPI validates the JSON against NormalizedAlert automatically.
    """
    try:
        result = classify_alert(alert.dict())
        return ClassificationResponse(
            alert_id=alert.alert_id,
            classification=result
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ── 3. Quick test using Phase 1 sample alerts (GET) ─────
@app.get("/classify/sample/{sample_name}",
         response_model=ClassificationResponse)
def classify_sample(sample_name: str):
    """
    Test without writing JSON by hand.
    Try: /classify/sample/ssh_brute_force
         /classify/sample/low_disk
         /classify/sample/rootkit_detection
    """
    if sample_name not in SAMPLE_ALERTS:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown sample '{sample_name}'. "
                   f"Valid: {list(SAMPLE_ALERTS.keys())}"
        )
    result = classify_alert(SAMPLE_ALERTS[sample_name])
    return ClassificationResponse(
        alert_id=SAMPLE_ALERTS[sample_name]["alert_id"],
        classification=result
    )
