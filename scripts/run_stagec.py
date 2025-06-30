#!/usr/bin/env python3

import sys
import json
from secelf.stage_c import (
    extract_metadata,
    extract_title,
    extract_description,
    extract_cvss_score,
    extract_references,
    extract_affected,
    is_cve_relevant,
)

def main():
    # Example test file path (you can change this later)
    test_cve_file = "cvelistV5/cves/2024/1xxx/CVE-2024-1492.json"

    try:
        with open(test_cve_file, "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Test CVE file not found: {test_cve_file}")
        sys.exit(1)

    print(">>> Metadata:", extract_metadata(data))
    print(">>> Title:", extract_title(data))
    print(">>> Description:", extract_description(data))
    print(">>> CVSS Score:", extract_cvss_score(data))
    print(">>> References:", extract_references(data))
    print(">>> Affected:", extract_affected(data))

    # load resolved packages from previous CSV
    resolved_packages = []
    with open("library_packages.csv", "r") as f:
        for row in json.load(f):
            pkg = row.get("ResolvedPackage", "").strip().lower()
            if pkg:
                resolved_packages.append(pkg)

    if is_cve_relevant(data, resolved_packages):
        print("CVE is relevant to one of our packages!")
    else:
        print("CVE not relevant.")

if __name__ == "__main__":
    main()
