#!/usr/bin/env python3

# build_detailed_stagec_table.py
# Build a compact detailed CVE table from Stage C outputs.
#
# Output:
#   outputs/stageC/detailed_cve_table.csv
#
# Columns:
#   Tool
#   ToolVersion
#   UpstreamProject
#   DependencyVersion
#   CVE ID
#   Published Date
#   CVSS Score
#   Problem Types
#   CWE
#   Title

import csv
import glob
import os


def main():
    out = "outputs/stageC/detailed_cve_table.csv"
    files = sorted(glob.glob("outputs/stageC/*/cve_matches.csv"))

    rows = []
    seen = set()

    for path in files:
        with open(path, newline="", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                key = (
                    row.get("Tool", ""),
                    row.get("ToolVersion", ""),
                    row.get("UpstreamProject", ""),
                    row.get("DependencyVersion", ""),
                    row.get("CVE ID", ""),
                )
                if key in seen:
                    continue
                seen.add(key)

                rows.append({
                    "Tool": row.get("Tool", ""),
                    "ToolVersion": row.get("ToolVersion", ""),
                    "UpstreamProject": row.get("UpstreamProject", ""),
                    "DependencyVersion": row.get("DependencyVersion", ""),
                    "CVE ID": row.get("CVE ID", ""),
                    "Published Date": row.get("Published Date", ""),
                    "CVSS Score": row.get("CVSS Score", ""),
                    "Problem Types": row.get("Problem Types", ""),
                    "CWE": row.get("CWE", ""),
                    "Title": row.get("Title", ""),
                })

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
                "CVSS Score",
                "Problem Types",
                "CWE",
                "Title",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"[OK] Wrote: {out}")
    print(f"[INFO] Rows: {len(rows)}")


if __name__ == "__main__":
    main()