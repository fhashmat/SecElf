import json
import csv


def extract_metadata(cve_json):
    meta = cve_json.get("cveMetadata", {})
    return {
        "cve_id": meta.get("cveId", ""),
        "published_date": meta.get("datePublished", "").split("T")[0]
    }

def extract_title(cve_json):
    return cve_json.get("containers", {}).get("cna", {}).get("title", "")

def extract_description(cve_json):
    descriptions = cve_json.get("containers", {}).get("cna", {}).get("descriptions", [])
    for desc in descriptions:
        if desc.get("lang", "").lower().startswith("en"):
            return desc.get("value", "")
    return "No English description found"

def extract_cvss_score(cve_json):
    metrics = cve_json.get("containers", {}).get("cna", {}).get("metrics", {})
    for version_key in ["cvssV31", "cvssV30", "cvssV2"]:
        if version_key in metrics:
            try:
                return metrics[version_key][0]["cvssData"]["baseScore"]
            except (IndexError, KeyError):
                continue
    return "N/A"

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

def is_cve_relevant(cve_json, resolved_packages):
    affected = cve_json.get("containers", {}).get("cna", {}).get("affected", [])
    for item in affected:
        product = item.get("product", "").lower()
        versions = item.get("versions", [])
        for version_info in versions:
            version = version_info.get("version", "").lower()
            full_package = f"{product}:{version}"
            if full_package in resolved_packages:
                return True
    title = extract_title(cve_json).lower()
    desc = extract_description(cve_json).lower()
    for pkg in resolved_packages:
        if pkg in title or pkg in desc:
            return True
    return False

def write_stagec_output_to_csv(results, output_file="stagec_output.csv"):
    """
    Takes a list of dictionaries (results) and writes to CSV.
    Each dictionary should include:
        - cve_id
        - published_date
        - title
        - description
        - cvss_score
        - references
        - affected
        - relevant (boolean)
    """
    headers = [
        "CVE ID",
        "Published Date",
        "Title",
        "Description",
        "CVSS Score",
        "References",
        "Affected",
        "Relevant"
    ]

    with open(output_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for item in results:
            writer.writerow({
                "CVE ID": item.get("cve_id", ""),
                "Published Date": item.get("published_date", ""),
                "Title": item.get("title", ""),
                "Description": item.get("description", ""),
                "CVSS Score": item.get("cvss_score", ""),
                "References": item.get("references", ""),
                "Affected": item.get("affected", ""),
                "Relevant": "Yes" if item.get("relevant") else "No"
            })
def write_stagec_output_to_csv_with_resolved_packages(results, output_file="stagec_output.csv"):
    """
    Writes CVE analysis results to a CSV file including resolved package name as the first column.

    Each entry in `results` should be a dictionary with:
        - resolved_package
        - cve_id
        - published_date
        - title
        - description
        - cvss_score
        - references
        - affected
        - relevant (bool)
    """
    headers = [
        "ResolvedPackage",
        "CVE ID",
        "Published Date",
        "Title",
        "Description",
        "CVSS Score",
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
                "References": item.get("references", ""),
                "Affected": item.get("affected", ""),
                "Relevant": "Yes" if item.get("relevant") else "No"
            })
