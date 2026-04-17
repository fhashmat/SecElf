#!/usr/bin/env python3

# summarize_stagec.py
# Summarize Stage C outputs per tool/version.
#
# Output:
#   outputs/stageC/all_stagec_summary.csv
#
# Columns:
#   Tool
#   Version
#   TotalCVEs
#   HighRiskCVEs
#   MaxHighRiskCVSS

import csv
import glob
import os


def main():
    files = sorted(glob.glob("outputs/stageC/*/cve_matches.csv"))
    out_csv = "outputs/stageC/all_stagec_summary.csv"

    rows = []

    for path in files:
        folder = os.path.basename(os.path.dirname(path))
        parts = folder.split("_")
        tool = parts[0]
        version = ".".join(parts[1:])

        total = 0
        high = 0
        max_high = ""

        with open(path, newline="", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                total += 1
                try:
                    score = float(row.get("CVSS Score", ""))
                    if score > 7.5:
                        high += 1
                        if max_high == "" or score > float(max_high):
                            max_high = score
                except Exception:
                    pass

        rows.append({
            "Tool": tool,
            "Version": version,
            "TotalCVEs": total,
            "HighRiskCVEs": high,
            "MaxHighRiskCVSS": max_high if max_high != "" else "N/A",
        })

    os.makedirs(os.path.dirname(out_csv), exist_ok=True)

    with open(out_csv, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "Tool",
                "Version",
                "TotalCVEs",
                "HighRiskCVEs",
                "MaxHighRiskCVSS",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"[OK] Wrote: {out_csv}")


if __name__ == "__main__":
    main()