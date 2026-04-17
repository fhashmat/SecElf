#!/usr/bin/env python3

# extract_high_risk_stagec.py
# Extract only high-risk CVE rows (CVSS > 7.5) from Stage C outputs.

import csv
import glob
import os

def main():
    out = "outputs/stageC/high_risk_cves_only.csv"
    files = sorted(glob.glob("outputs/stageC/*/cve_matches.csv"))

    rows = []
    for path in files:
        with open(path, newline="", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    score = float(row.get("CVSS Score", ""))
                    if score > 7.5:
                        rows.append(row)
                except Exception:
                    pass

    os.makedirs(os.path.dirname(out), exist_ok=True)

    with open(out, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "Tool",
                "ToolVersion",
                "UpstreamProject",
                "DependencyVersion",
                "CVE ID",
                "Published Date",
                "Title",
                "Description",
                "CVSS Score",
                "Problem Types",
                "CWE",
                "References",
                "Affected",
                "Relevant",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"[OK] Wrote: {out}")
    print(f"[INFO] High-risk rows: {len(rows)}")

if __name__ == "__main__":
    main()