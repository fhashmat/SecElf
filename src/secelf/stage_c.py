import json

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