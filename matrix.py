import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay

# Manual ground truth — 8 entries
y_true = [
    "TRUE POSITIVE",
    "FALSE POSITIVE",
    "TRUE POSITIVE",
    "NEEDS INVESTIGATION",
    "TRUE POSITIVE",
    "FALSE POSITIVE",
    "NEEDS INVESTIGATION",
    "TRUE POSITIVE"
]

# Gemini's actual output — 8 entries
y_pred = [
    "TRUE POSITIVE",
    "NEEDS INVESTIGATION",
    "TRUE POSITIVE",
    "NEEDS INVESTIGATION",
    "FALSE POSITIVE",
    "FALSE POSITIVE",
    "NEEDS INVESTIGATION",
    "TRUE POSITIVE"
]

labels = [
    "TRUE POSITIVE",
    "FALSE POSITIVE",
    "NEEDS INVESTIGATION"
]

cm = confusion_matrix(y_true, y_pred, labels=labels)

disp = ConfusionMatrixDisplay(
    confusion_matrix=cm,
    display_labels=["TP", "FP", "NEEDS INV."]
)

disp.plot(cmap="Blues", values_format="d")

plt.tight_layout()
plt.savefig("confusion_matrix.png", dpi=300)
plt.show()
