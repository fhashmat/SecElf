#!/usr/bin/env python3

import sys
import json
import csv
import pprint
from secelf.stage_c import (
    extract_metadata,
    extract_title,
    extract_description,
    extract_cvss_score,
    extract_references,
    extract_affected,
    is_cve_relevant,
    extract_cwe,
    write_stagec_output_to_csv_with_resolved_packages,
)

def main():
    # Example test file path (you can change this later)
    test_cve_file = "cvelistV5/cves/2024/1xxx/CVE-2024-1492.json"

    try:
        with open(test_cve_file, "r") as f:
            data = json.load(f)
        pprint.pprint(data)
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
    results = []
    with open("resolved_libs.tsv", "r") as f:
        reader = csv.DictReader(f, delimiter='\t')  # important: tab delimiter
        for row in reader:
            resolved_pkg = row.get("BINARY_PACKAGE", "").strip().lower()
            if not resolved_pkg:
                resolved_pkg = row.get("SOURCE_PACKAGE", "").strip().lower()
            if not resolved_pkg:
                continue

            relevance = is_cve_relevant(data, [resolved_pkg])

            results.append({
                "resolved_package": resolved_pkg,
                "cve_id": extract_metadata(data).get("cve_id", ""),
                "published_date": extract_metadata(data).get("published_date", ""),
                "title": extract_title(data),
                "description": extract_description(data),
                "cvss_score": extract_cvss_score(data),
                "cwe": extract_cwe(data),
                "references": extract_references(data),
                "affected": extract_affected(data),
                "relevant": relevance
})


    write_stagec_output_to_csv_with_resolved_packages(results)
if __name__ == "__main__":
    main()
