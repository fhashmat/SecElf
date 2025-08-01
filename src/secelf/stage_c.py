import json
import csv
import re

def normalize_package_name(pkg_name):
    """
    Converts package name like 'glibc-2.28-251.0.3.el8_10.22.x86_64'
    into 'glibc:2.28'
    """
    pkg_name = re.sub(r"\.x86_64$|\.i686$|\.aarch64$|\.armv7hl$", "", pkg_name)
    match = re.match(r"^([a-zA-Z0-9_\+\-\.]+)-(\d+\.\d+(?:\.\d+)?)", pkg_name)
    if match:
        product = match.group(1)
        version = match.group(2)
        return f"{product}:{version}".lower()
    return pkg_name.lower()

def extract_metadata(cve_json):
    meta = cve_json.get("cveMetadata", {})
    return {
        "cve_id": meta.get("cveId", ""),
        "published_date": meta.get("datePublished", "").split("T")[0]
    }

def extract_description(cve_json):
    descriptions = cve_json.get("containers", {}).get("cna", {}).get("descriptions", [])
    for desc in descriptions:
        if desc.get("lang", "").lower().startswith("en"):
            return desc.get("value", "")
    return "No English description found"

def extract_cvss_score(data):
    try:
        metrics = data["containers"]["cna"].get("metrics", [])
        for entry in metrics:
            if "cvssV3_1" in entry:
                return entry["cvssV3_1"].get("baseScore", "N/A")
        return "N/A"
    except Exception:
        return "N/A"

def extract_cwe(data):
    try:
        problem_types = data["containers"]["cna"].get("problemTypes", [])
        for pt in problem_types:
            for desc in pt.get("descriptions", []):
                if "description" in desc:
                    return desc["description"]
        return ""
    except Exception:
        return ""

def extract_references(cve_json):
    refs = cve_json.get("containers", {}).get("cna", {}).get("references", [])
    urls = [ref.get("url", "") for ref in refs if "url" in ref]
    return "; ".join(urls)

def extract_affected(cve_json):
    affected_data = []
    affected = cve_json.get("containers", {}).get("cna", {}).get("affected", [])
    for item in affected:
        vendor = item.get("vendor", "")
        product = item.get("product", "")
        for version_info in item.get("versions", []):
            version = version_info.get("version", "")
            status = version_info.get("status", "")
            entry = f"{vendor}:{product}:{version}:{status}"
            affected_data.append(entry)
    return "; ".join(affected_data)

def is_cve_relevant(cve_json, resolved_packages, debug=False):
    if isinstance(cve_json, list):
        cve_json = next((item for item in cve_json if isinstance(item, dict)), {})
    elif not isinstance(cve_json, dict):
        if debug:
            print("[WARN] Skipping non-dict CVE entry")
        return False

    normalized_pkgs = [pkg.lower() for pkg in resolved_packages]
    if debug:
        print(f"[DEBUG] Normalized packages: {normalized_pkgs}")

    containers = cve_json.get("containers", {})
    if isinstance(containers, list):
        containers = next((item for item in containers if isinstance(item, dict) and "cna" in item), {})
    elif not isinstance(containers, dict):
        containers = {}

    affected = containers.get("cna", {}).get("affected", [])

    for item in affected:
    # Prefer `product`, fallback to `packageName`
        product = item.get("product") or item.get("packageName") or ""
        product = product.lower()
        versions = item.get("versions", [])
        for version_info in versions:
            version = version_info.get("version", "").lower()
            full = f"{product}:{version}"
            if debug:
                print(f"[DEBUG] Affected product:version = {full}")
            if full in normalized_pkgs:
                if debug:
                    print(f"[MATCH] Direct match found: {full}")
                return True

        for version_info in versions:
            version = version_info.get("version", "").lower()

            # If product is empty, try using vendor, or skip
            if not product:
                if vendor:
                    product = vendor
                else:
                    continue

            full = f"{product}:{version}"
            if debug:
                print(f"[DEBUG] Affected product:version = {full}")
            for norm_pkg in normalized_pkgs:
                if norm_pkg == full or full.startswith(norm_pkg + ".") or full.startswith(norm_pkg + ":"):
                    if debug:
                        print(f"[MATCH] Found match: {norm_pkg} in {full}")
                    return True

    return False



def extract_title(data):
    try:
        return data["containers"]["cna"].get("title", "")
    except Exception:
        return ""

def extract_problem_types(cve_json):
    try:
        problems = cve_json.get("containers", {}).get("cna", {}).get("problemTypes", [])
        descriptions = []
        for entry in problems:
            for desc in entry.get("descriptions", []):
                if "description" in desc:
                    descriptions.append(desc["description"])
        return "; ".join(descriptions) if descriptions else "N/A"
    except Exception:
        return "N/A"

def write_stagec_output_to_csv_with_resolved_packages(results, output_file="stagec_output.csv"):
    headers = [
        "ResolvedPackage",
        "CVE ID",
        "Published Date",
        "Title",
        "Description",
        "CVSS Score",
        "Problem Types",
        "CWE",
        "References",
        "Affected",
        "Relevant"
    ]

    with open(output_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for item in results:
            writer.writerow({
                "ResolvedPackage": item.get("resolved_package", ""),
                "CVE ID": item.get("cve_id", ""),
                "Published Date": item.get("published_date", ""),
                "Title": item.get("title", ""),
                "Description": item.get("description", ""),
                "CVSS Score": item.get("cvss_score", ""),
                "CWE": item.get("cwe", ""),
                "Problem Types": item.get("problem_types", ""),
                "References": item.get("references", ""),
                "Affected": item.get("affected", ""),
                "Relevant": "Yes" if item.get("relevant") else "No"
            })
