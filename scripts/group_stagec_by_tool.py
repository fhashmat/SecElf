#!/usr/bin/env python3

# group_stagec_by_tool.py
# Build one-row-per-tool grouped Stage C table.
#
# Output:
#   outputs/stageC/grouped_stagec_by_tool.csv
#
# Columns:
#   Tool
#   ToolVersion
#   Dependency
#   CVE IDs (score)
#   CVSS
#   CWE / Problem Type
#   Title

import csv
import os
from collections import OrderedDict

IN_CSV = "outputs/stageC/detailed_cve_table.csv"
OUT_CSV = "outputs/stageC/grouped_stagec_by_tool.csv"


def uniq_preserve(seq):
    seen = set()
    out = []
    for x in seq:
        x = (x or "").strip()
        if not x or x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out


def main():
    grouped = OrderedDict()

    with open(IN_CSV, newline="", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            key = (row.get("Tool", "").strip(), row.get("ToolVersion", "").strip())

            if key not in grouped:
                grouped[key] = {
                    "dependencies": [],
                    "cve_ids_scores": [],
                    "cvss": [],
                    "cwe_problem": [],
                    "titles": [],
                }

            dep = f"{row.get('UpstreamProject', '').strip()} ({row.get('DependencyVersion', '').strip()})"
            cve = row.get("CVE ID", "").strip()
            score = row.get("CVSS Score", "").strip()
            cve_score = f"{cve} ({score})" if cve and score else cve

            grouped[key]["dependencies"].append(dep)
            grouped[key]["cve_ids_scores"].append(cve_score)
            if score:
                grouped[key]["cvss"].append(score)

            cwe = row.get("CWE", "").strip()
            ptype = row.get("Problem Types", "").strip()
            if cwe and ptype and cwe != ptype:
                grouped[key]["cwe_problem"].append(f"{cwe}; {ptype}")
            elif cwe:
                grouped[key]["cwe_problem"].append(cwe)
            elif ptype:
                grouped[key]["cwe_problem"].append(ptype)

            title = row.get("Title", "").strip()
            if title:
                grouped[key]["titles"].append(title)

    rows = []
    for (tool, version), data in grouped.items():
        rows.append({
            "Tool": tool,
            "ToolVersion": version,
            "Dependency": "; ".join(uniq_preserve(data["dependencies"])),
            "CVE IDs (score)": "; ".join(uniq_preserve(data["cve_ids_scores"])),
            "CVSS": "; ".join(uniq_preserve(data["cvss"])),
            "CWE / Problem Type": "; ".join(uniq_preserve(data["cwe_problem"])),
            "Title": "; ".join(uniq_preserve(data["titles"])),
        })

    os.makedirs(os.path.dirname(OUT_CSV), exist_ok=True)
    with open(OUT_CSV, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "Tool",
                "ToolVersion",
                "Dependency",
                "CVE IDs (score)",
                "CVSS",
                "CWE / Problem Type",
                "Title",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"[OK] Wrote: {OUT_CSV}")
    print(f"[INFO] Rows: {len(rows)}")


if __name__ == "__main__":
    main()