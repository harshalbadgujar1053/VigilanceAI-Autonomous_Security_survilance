"""
Adds the ClassificationQueue table definition to backend/database.py.
Safe to run once; refuses if already present.

Usage:
    python3 patch_database_for_queue.py /home/kali/VigilanceAI-Autonomous_Security_survilance/backend/database.py
"""
import sys

ANCHOR = 'class ReportRecord(Base):'

NEW_CLASS = '''class ClassificationQueue(Base):
    __tablename__ = "classification_queue"
    id           = Column(Integer, primary_key=True, autoincrement=True)
    alert_id     = Column(String, nullable=False)
    status       = Column(String, default="pending")  # pending | processing | done | failed
    attempts     = Column(Integer, default=0)
    enqueued_at  = Column(DateTime, default=datetime.utcnow)
    updated_at   = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    error        = Column(Text, nullable=True)

class ReportRecord(Base):'''


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 patch_database_for_queue.py <path-to-database.py>")
        sys.exit(1)

    path = sys.argv[1]
    with open(path, "r") as f:
        content = f.read()

    if "class ClassificationQueue(Base):" in content:
        print("ClassificationQueue already present — nothing to do.")
        return

    if ANCHOR not in content:
        print(f"ERROR: could not find anchor '{ANCHOR}' in {path}. "
              "Paste the current file and I'll adjust the script.")
        sys.exit(1)

    backup_path = path + ".bak_before_queue_patch"
    with open(backup_path, "w") as f:
        f.write(content)
    print(f"Backup written to {backup_path}")

    new_content = content.replace(ANCHOR, NEW_CLASS, 1)
    with open(path, "w") as f:
        f.write(new_content)

    print(f"Patched {path} successfully — ClassificationQueue table added.")
    print("Now run: python3 -c \"from database import init_db; init_db()\" to create the table.")


if __name__ == "__main__":
    main()
