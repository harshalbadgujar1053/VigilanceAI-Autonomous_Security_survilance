VigilanceAI

![Cybersecurity](https://img.shields.io/badge/Cybersecurity-black?style=flat-square)
![SOC](https://img.shields.io/badge/SOC-black?style=flat-square)
![SIEM](https://img.shields.io/badge/SIEM-black?style=flat-square)
![Wazuh](https://img.shields.io/badge/Wazuh-005571?style=flat-square)
![RAG](https://img.shields.io/badge/RAG-blueviolet?style=flat-square)
![LLM](https://img.shields.io/badge/LLM-orange?style=flat-square)
![ChromaDB](https://img.shields.io/badge/ChromaDB-yellow?style=flat-square)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-red?style=flat-square)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-61DAFB?style=flat-square&logo=react&logoColor=black)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?style=flat-square&logo=postgresql&logoColor=white)
![Gemini](https://img.shields.io/badge/Gemini-8E75B2?style=flat-square&logo=googlegemini&logoColor=white)

Problem Statement

Modern Security Operations Centres are overwhelmed by the volume of alerts SIEM systems generate, with analysts spending a large share of their time investigating alerts that turn out to be false positives — causing alert fatigue and delayed response to genuine threats. Existing LLM-based approaches to alert classification typically let the model freely name the attack technique behind an alert, a free-text generation step with no way to verify the claim against an authoritative source — reintroducing a hallucination problem at exactly the point where traceability matters most.

Solution

VigilanceAI is a RAG-grounded alert classification pipeline built on top of Wazuh SIEM telemetry. Rather than letting an LLM choose the MITRE ATT&CK technique behind an alert, the pipeline retrieves the most similar technique from a ChromaDB knowledge base via embedding similarity and injects it into the classification prompt as a mandatory, non-negotiable field — so the reported technique always traces back to a specific document rather than being an artifact of unrestricted generation. The LLM (Gemini 3.5 Flash Lite) then reasons only about the alert relative to that grounded technique, producing a verdict, categorical confidence, severity, natural-language reasoning, and recommended action. Final confidence is computed as the minimum of the LLM's self-reported confidence and the retrieval similarity score, so a confident-sounding but poorly-grounded classification can never receive an undeserved HIGH confidence label. Each classification is persisted and converted into a NIST-compliant (Who/What/When/Where/How) incident report with a six-stage incident-response breakdown.

Pipeline

Wazuh agent detects an alert → wazuh_forwarder.py posts it unmodified to a FastAPI ingestion endpoint → FastAPI acknowledges immediately and classifies asynchronously via BackgroundTask + thread pool (so the synchronous Gemini call never blocks new alert ingestion) → alert text is embedded with all-MiniLM-L6-v2 and matched via cosine similarity against ChromaDB → top-1 technique is injected into the Gemini prompt → verdict/confidence is computed → result is persisted in PostgreSQL, linked by alert ID to the original Wazuh record → React/TypeScript dashboard renders the alert with verdict/severity badges and generates PDF reports on demand.

Reliability

HTTP 429 responses from the classification API trigger exponential backoff retries (5s, 10s, 20s); alerts that fail all three attempts persist with a PENDING status rather than being dropped.

Tech stack

SIEM: Wazuh. LLM: Gemini 3.5 Flash Lite (selected after benchmarking against six other local/cloud models — 91.2 composite score, 88% MITRE technique accuracy, 1.84s average latency). Retrieval: ChromaDB with all-MiniLM-L6-v2 sentence embeddings over MITRE ATT&CK (697 techniques), CAPEC (557 patterns), CWE (944 weaknesses), and NVD CVE (6,000 records) — 8,198 documents total. Backend: FastAPI (async, thread-pool isolated LLM calls). Database: PostgreSQL 18. Frontend: React/TypeScript. Reporting: jsPDF for automated NIST-compliant incident reports.
