#!/usr/bin/env python3

import sys
import json
import os
import csv
import re
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

# ✅ Normalize package names to match CVE product:version
def normalize_package_name(pkg_name):
    pkg_name = re.sub(r"\.x86_64$|\.i686$|\.aarch64$|\.armv7hl$", "", pkg_name)
    match = re.match(r"^([a-zA-Z0-9_\+\-\.]+)-(\d+\.\d+)", pkg_name)
    if match:
        base = match.group(1)
        version = match.group(2)
        return f"{base}:{version}"
    return pkg_name

def load_resolved_packages(tsv_path):
    resolved_packages = []
    with open(tsv_path, "r") as f:
        reader = csv.DictReader(f, delimiter='\t')
        for row in reader:
            pkg = row.get("BINARY_PACKAGE", "").strip().lower()
            if not pkg:
                pkg = row.get("SOURCE_PACKAGE", "").strip().lower()
            if pkg:
                resolved_packages.append(pkg)
    return resolved_packages

def main():
    resolved_packages_raw = load_resolved_packages("resolved_libs.tsv")
    resolved_packages = [normalize_package_name(pkg) for pkg in resolved_packages_raw]

    print(f"[INFO] Loaded {len(resolved_packages)} resolved packages (normalized)")
    print("[DEBUG] First few normalized packages:")
    for pkg in resolved_packages[:5]:
        print("   ", pkg)

    cve_dir = "cvelistV5/cves"
    results = []

    all_json_files = []
    for root, _, files in os.walk(cve_dir):
        for filename in files:
            if filename.endswith(".json"):
                all_json_files.append(os.path.join(root, filename))

    for cve_path in tqdm(all_json_files, desc="Processing CVEs"):
        try:
            with open(cve_path, "r") as f:
                cve_data = json.load(f)
        except Exception as e:
            print(f"[WARN] Skipping {os.path.basename(cve_path)}: {e}")
            continue

        for pkg in resolved_packages:
            relevant = is_cve_relevant(cve_data, [pkg])
            if relevant:
                results.append({
                    "resolved_package": pkg,
                    "cve_id": extract_metadata(cve_data).get("cve_id", ""),
                    "published_date": extract_metadata(cve_data).get("published_date", ""),
                    "title": extract_title(cve_data),
                    "description": extract_description(cve_data),
                    "cvss_score": extract_cvss_score(cve_data),
                    "cwe": extract_cwe(cve_data),
                    "references": extract_references(cve_data),
                    "affected": extract_affected(cve_data),
                    "relevant": True,
                    "problem_types": extract_problem_types(cve_data),
                })

    print(f"[INFO] Found {len(results)} relevant CVE matches")
    write_stagec_output_to_csv_with_resolved_packages(results)

if __name__ == "__main__":
    main()
