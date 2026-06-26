"""Canonical schema for the CIC-IDS2017 MachineLearningCVE web-attacks file.

The real file is `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv`.
Column names in the raw file carry leading spaces; everything here is the
stripped form that the loader normalises to.
"""

# 78 flow features extracted by CICFlowMeter (stripped names).
FEATURE_COLUMNS = [
    "Destination Port", "Flow Duration", "Total Fwd Packets",
    "Total Backward Packets", "Total Length of Fwd Packets",
    "Total Length of Bwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
    "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total",
    "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total",
    "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags",
    "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length",
    "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s", "Min Packet Length",
    "Max Packet Length", "Packet Length Mean", "Packet Length Std",
    "Packet Length Variance", "FIN Flag Count", "SYN Flag Count",
    "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
    "CWE Flag Count", "ECE Flag Count", "Down/Up Ratio", "Average Packet Size",
    "Avg Fwd Segment Size", "Avg Bwd Segment Size", "Fwd Header Length.1",
    "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets",
    "Subflow Bwd Bytes", "Init_Win_bytes_forward", "Init_Win_bytes_backward",
    "act_data_pkt_fwd", "min_seg_size_forward", "Active Mean", "Active Std",
    "Active Max", "Active Min", "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
]

LABEL_COLUMN = "Label"
BENIGN_LABEL = "BENIGN"

# Documented per-class row counts for the real web-attacks file. These are the
# counts widely reported in the literature and reproduced by the synthetic
# generator so the demonstration mirrors the real class imbalance.
REAL_CLASS_COUNTS = {
    "BENIGN": 168186,
    "Web Attack - Brute Force": 1507,
    "Web Attack - XSS": 652,
    "Web Attack - Sql Injection": 21,
}


def normalise_label(label: str) -> str:
    """Collapse the en-dash / hyphen variants the raw file ships with."""
    return " ".join(str(label).replace("\x96", "-").replace("\u2013", "-").split())


def is_attack(label: str) -> bool:
    """True for any web-attack subclass, False for benign traffic."""
    return normalise_label(label).lower().startswith("web attack")
