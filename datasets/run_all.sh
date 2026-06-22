#!/bin/bash
echo "======================================"
echo " VigilanceAI - Dataset Exploration"
echo "======================================"

echo ""
echo "[1/3] MITRE ATT&CK STIX Bundle..."
python3 explore_mitre_attack.py

echo ""
echo "[2/3] NVD CVE Feed..."
python3 explore_nvd_cve.py

echo ""
echo "[3/3] CICIDS-2018..."
python3 explore_cicids2018.py

echo ""
echo "Done. Check outputs above for any errors."
