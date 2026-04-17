#!/usr/bin/env python3

# run_stagec.py
# Stage C runner:
#   Read Stage B1 dependency metadata
#   Match CVEs against UpstreamProject + DependencyVersion
#   Write rich CVE output per tool/version

import os
import csv
import json
from tqdm import tqdm

from secelf.stage_c import (
    extract_metadata,
    extract_title,
    extract_description,
    extract_cvss_score,
    extract_references,
    extract_affected,
    extract_problem_types,
    extract_cwe,
    is_cve_relevant,
    write_stagec_output_to_csv_with_resolved_packages,
)

targets = [
    ("Genus", "21.17", "outputs/stageB1/genus_21_17/dependency_risk_metadata.csv"),
    ("Innovus", "21.12", "outputs/stageB1/innovus_21_12/dependency_risk_metadata.csv"),
    ("Innovus", "21.17", "outputs/stageB1/innovus_21_17/dependency_risk_metadata.csv"),
    ("Jasper", "2024.12", "outputs/stageB1/jasper_2024_12/dependency_risk_metadata.csv"),
    ("Assura", "6.18.4.16", "outputs/stageB1/assura_6_18_4_16/dependency_risk_metadata.csv"),
    ("Assura", "23.1.4.17", "outputs/stageB1/assura_23_1_4_17/dependency_risk_metadata.csv"),
]

def load_dependencies(b1_csv):
    """
    Load unique dependencies from Stage B1 using:
      UpstreamProject + VersionOnly
    """
    deps = []
    seen = set()

    with open(b1_csv, newline="", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            project = (row.get("UpstreamProject") or "").strip().lower()
            version = (row.get("VersionOnly") or "").strip().lower()

            if not project or not version:
                continue

            key = (project, version)
            if key in seen:
                continue
            seen.add(key)

            deps.append({
                "upstream_project": project,
                "dependency_version": version,
            })

    return deps

def main():
    cve_dir = "cvelistV5/cves"

    all_json_files = []
    for root, _, files in os.walk(cve_dir):
        for filename in files:
            if filename.endswith(".json"):
                all_json_files.append(os.path.join(root, filename))

    print(f"[INFO] CVE files discovered: {len(all_json_files)}")

    for tool, version, b1_csv in targets:
        if not os.path.exists(b1_csv):
            print(f"[WARN] Missing Stage B1 file for {tool} {version}: {b1_csv}")
            continue

        print(f"[RUN] Stage C -> {tool} {version}")
        deps = load_dependencies(b1_csv)
        print(f"[INFO] Unique dependencies loaded: {len(deps)}")

        results = []

        for cve_path in tqdm(all_json_files, desc=f"Processing CVEs for {tool} {version}"):
            try:
                with open(cve_path, "r", encoding="utf-8") as f:
                    cve_data = json.load(f)
            except Exception:
                continue

            meta = extract_metadata(cve_data)
            title = extract_title(cve_data)
            desc = extract_description(cve_data)
            cvss = extract_cvss_score(cve_data)
            cwe = extract_cwe(cve_data)
            refs = extract_references(cve_data)
            aff = extract_affected(cve_data)
            probs = extract_problem_types(cve_data)

            for dep in deps:
                pkg_for_match = f"{dep['upstream_project']}:{dep['dependency_version']}"
                relevant = is_cve_relevant(cve_data, [pkg_for_match])

                if relevant:
                    results.append({
                        "tool": tool,
                        "tool_version": version,
                        "upstream_project": dep["upstream_project"],
                        "dependency_version": dep["dependency_version"],
                        "cve_id": meta.get("cve_id", ""),
                        "published_date": meta.get("published_date", ""),
                        "title": title,
                        "description": desc,
                        "cvss_score": cvss,
                        "cwe": cwe,
                        "problem_types": probs,
                        "references": refs,
                        "affected": aff,
                        "relevant": True,
                    })

        out_dir = os.path.join("outputs", "stageC", f"{tool.lower()}_{version.replace('.', '_')}")
        os.makedirs(out_dir, exist_ok=True)
        out_csv = os.path.join(out_dir, "cve_matches.csv")

        print(f"[INFO] Found {len(results)} relevant CVE matches for {tool} {version}")
        write_stagec_output_to_csv_with_resolved_packages(results, output_file=out_csv)
        print(f"[OK] Wrote: {out_csv}")

if __name__ == "__main__":
    main()