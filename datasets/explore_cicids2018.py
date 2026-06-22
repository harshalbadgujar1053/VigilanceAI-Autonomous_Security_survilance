"""
explore_cicids2018.py
Parses a CICIDS-2018 CSV file and prints 10 sample rows.

DOWNLOAD INSTRUCTIONS (manual step required):
  Option A - AWS CLI (official CIC source):
    sudo apt install awscli -y
    aws s3 cp "s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv" \
        ~/VigilanceAI/datasets/CICIDS2018_sample.csv --no-sign-request

  Option B - Kaggle mirror (faster):
    pip install kaggle
    kaggle datasets download -d dhoogla/cicidss2018 -p ~/VigilanceAI/datasets/
    unzip ~/VigilanceAI/datasets/cicidss2018.zip -d ~/VigilanceAI/datasets/
    mv ~/VigilanceAI/datasets/*.csv ~/VigilanceAI/datasets/CICIDS2018_sample.csv

After downloading, run: python3 explore_cicids2018.py
"""

import csv
import os
import sys

CSV_FILENAME = "CICIDS2018_sample.csv"
CSV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), CSV_FILENAME)


def print_sample(csv_path, limit=10):
    if not os.path.exists(csv_path):
        print(f"[error] File not found: {csv_path}")
        print()
        print("Download it first using one of these methods:")
        print()
        print("  Option A - AWS CLI:")
        print("    sudo apt install awscli -y")
        print('    aws s3 cp "s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv" \\')
        print("        ~/VigilanceAI/datasets/CICIDS2018_sample.csv --no-sign-request")
        print()
        print("  Option B - Kaggle:")
        print("    pip install kaggle")
        print("    kaggle datasets download -d dhoogla/cicidss2018 -p ~/VigilanceAI/datasets/")
        sys.exit(1)

    with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        columns = reader.fieldnames

        print(f"[info] Detected {len(columns)} columns.")
        print(f"[info] Columns: {columns}\n")
        print(f"=== Showing {limit} sample rows ===\n")

        for i, row in enumerate(reader, start=1):
            if i > limit:
                break
            label = row.get("Label", row.get(" Label", "N/A")).strip()
            duration = row.get("Flow Duration", row.get(" Flow Duration", "N/A"))
            src_ip = row.get("Src IP", row.get(" Src IP", "N/A"))
            dst_port = row.get("Dst Port", row.get(" Dst Port", "N/A"))

            print(f"{i}. Label: {label:20} | Src IP: {src_ip:15} | "
                  f"Dst Port: {dst_port:6} | Duration: {duration}")


if __name__ == "__main__":
    print_sample(CSV_PATH, limit=10)
