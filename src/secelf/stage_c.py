import json
import csv
import re
import os
import glob

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

def coerce_cve_dict(cve_json):
    """
    Some CVE JSON files load as a list of dicts instead of one dict.
    Return the first dict-like CVE entry.
    """
    if isinstance(cve_json, list):
        for item in cve_json:
            if isinstance(item, dict):
                return item
        return {}
    if isinstance(cve_json, dict):
        return cve_json
    return {}

def extract_metadata(cve_json):
    cve_json = coerce_cve_dict(cve_json)
    meta = cve_json.get("cveMetadata", {})
    return {
        "cve_id": meta.get("cveId", ""),
        "published_date": meta.get("datePublished", "").split("T")[0]
    }

def extract_description(cve_json):
    cve_json = coerce_cve_dict(cve_json)
    descriptions = cve_json.get("containers", {}).get("cna", {}).get("descriptions", [])
    for desc in descriptions:
        if desc.get("lang", "").lower().startswith("en"):
            return desc.get("value", "")
    return "No English description found"
def extract_problem_types(cve_json):
    cve_json = coerce_cve_dict(cve_json)
    """
    Extract problem type descriptions from CNA container.
    """
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

def extract_title(data):
    data = coerce_cve_dict(data)
    """
    Extract CVE title from CNA container.
    """
    try:
        return data.get("containers", {}).get("cna", {}).get("title", "")
    except Exception:
        return ""
def extract_cvss_score(data):
    data = coerce_cve_dict(data)
    try:
        metrics = data["containers"]["cna"].get("metrics", [])
        for entry in metrics:
            if "cvssV3_1" in entry:
                return entry["cvssV3_1"].get("baseScore", "N/A")
        return "N/A"
    except Exception:
        return "N/A"

def extract_cwe(data):
    data = coerce_cve_dict(data)
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
    cve_json = coerce_cve_dict(cve_json)
    refs = cve_json.get("containers", {}).get("cna", {}).get("references", [])
    urls = [ref.get("url", "") for ref in refs if "url" in ref]
    return "; ".join(urls)

def extract_affected(cve_json):
    cve_json = coerce_cve_dict(cve_json)
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

def normalize_version_token(version_str):
    """
    Reduce a version string to a comparable numeric token.

    Examples:
        2.35-0ubuntu3.13 -> 2.35
        1:1.2.11.dfsg-2ubuntu9.2 -> 1.2.11
        6.3-2ubuntu0.1 -> 6.3
    """
    if not version_str:
        return ""
    m = re.search(r"\d+\.\d+(?:\.\d+)?", str(version_str))
    return m.group(0).lower() if m else str(version_str).lower()


def compare_versions(v1, v2):
    """
    Compare two normalized numeric version strings.

    Returns:
        -1 if v1 < v2
         0 if v1 == v2
         1 if v1 > v2
    """
    def parts(v):
        return [int(x) for x in v.split(".") if x.isdigit()]

    p1 = parts(v1)
    p2 = parts(v2)

    n = max(len(p1), len(p2))
    p1 += [0] * (n - len(p1))
    p2 += [0] * (n - len(p2))

    if p1 < p2:
        return -1
    if p1 > p2:
        return 1
    return 0

def is_cve_relevant(cve_json, resolved_packages, debug=False):
    """
    Match one or more dependency identities against CVE affected blocks.

    Expected dependency format:
        upstream_project:dependency_version

    Matching logic:
        1. Match against affected.product or affected.packageName
        2. If product is empty, fall back to vendor
        3. Evaluate affected version rules using:
           - version
           - lessThan
           - lessThanOrEqual
        4. Ignore version entries explicitly marked as unaffected
    """
    if isinstance(cve_json, list):
        cve_json = next((item for item in cve_json if isinstance(item, dict)), {})
    elif not isinstance(cve_json, dict):
        if debug:
            print("[WARN] Skipping non-dict CVE entry")
        return False

    containers = cve_json.get("containers", {})
    if isinstance(containers, list):
        containers = next((item for item in containers if isinstance(item, dict) and "cna" in item), {})
    elif not isinstance(containers, dict):
        containers = {}

    affected = containers.get("cna", {}).get("affected", [])

    normalized_pkgs = []
    for pkg in resolved_packages:
        pkg = (pkg or "").strip().lower()
        if ":" not in pkg:
            continue
        proj, ver = pkg.split(":", 1)
        normalized_pkgs.append((proj.strip(), normalize_version_token(ver.strip())))

    for item in affected:
        product = (item.get("product") or item.get("packageName") or "").strip().lower()
        vendor = (item.get("vendor") or "").strip().lower()
        candidate_name = product if product else vendor

        if not candidate_name:
            continue

        versions = item.get("versions", [])

        for dep_project, dep_version in normalized_pkgs:
            if dep_project != candidate_name:
                continue

            for version_info in versions:
                status = (version_info.get("status") or "").strip().lower()
                if status == "unaffected":
                    continue

                ver = normalize_version_token(version_info.get("version", ""))
                less_than = normalize_version_token(version_info.get("lessThan", ""))
                less_than_eq = normalize_version_token(version_info.get("lessThanOrEqual", ""))

                # Exact/same-version style match
                if ver:
                    if dep_version == ver or dep_version.startswith(ver) or ver.startswith(dep_version):
                        return True

                # Range match: affected if dependency version is below upper bound
                if less_than:
                    if compare_versions(dep_version, less_than) < 0:
                        return True

                # Range match: affected if dependency version is <= upper bound
                if less_than_eq:
                    if compare_versions(dep_version, less_than_eq) <= 0:
                        return True

                # If the CVE says affected but gives no version details, keep as a weak match
                if status == "affected" and not ver and not less_than and not less_than_eq:
                    return True

    return False
def write_stagec_output_to_csv_with_resolved_packages(results, output_file="stagec_output.csv"):
    headers = [
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
        "Relevant"
    ]

    with open(output_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for item in results:
            writer.writerow({
                "Tool": item.get("tool", ""),
                "ToolVersion": item.get("tool_version", ""),
                "UpstreamProject": item.get("upstream_project", ""),
                "DependencyVersion": item.get("dependency_version", ""),
                "CVE ID": item.get("cve_id", ""),
                "Published Date": item.get("published_date", ""),
                "Title": item.get("title", ""),
                "Description": item.get("description", ""),
                "CVSS Score": item.get("cvss_score", ""),
                "Problem Types": item.get("problem_types", ""),
                "CWE": item.get("cwe", ""),
                "References": item.get("references", ""),
                "Affected": item.get("affected", ""),
                "Relevant": "Yes" if item.get("relevant") else "No"
            })

if __name__ == "__main__":
    # Usage:
    #   PYTHONPATH=src python3 src/secelf/stage_c.py </path/to/binary | stageBlibs/.../packages_*.csv> [</path/to/cvelistV5>]
    import sys

    if len(sys.argv) < 2:
        print("Usage: PYTHONPATH=src python3 src/secelf/stage_c.py </path/to/binary | stageBlibs/.../packages_*.csv> [</path/to/cvelistV5>]")
        sys.exit(1)

    arg = sys.argv[1]
    cvelist_root = sys.argv[2] if len(sys.argv) >= 3 else "cvelistV5"

    # Case A: user passed Stage B CSV directly
    if os.path.isfile(arg) and arg.endswith(".csv"):
        pkgs_csv = arg
        # derive names from CSV path
        fname = os.path.basename(pkgs_csv)              # packages_<binary>.csv
        base  = os.path.splitext(fname)[0]              # packages_<binary>
        binary_name = base[len("packages_"):] if base.startswith("packages_") else base
        tool_name = os.path.basename(os.path.dirname(pkgs_csv))
    else:
        # Case B: user passed a binary path -> build Stage B path
        binary_name = os.path.basename(arg)
        tool_name   = os.path.splitext(binary_name)[0]
        pkgs_csv    = os.path.join("stageBlibs", tool_name, f"packages_{binary_name}.csv")
        if not os.path.exists(pkgs_csv):
            # Fallback: search anywhere under stageBlibs for packages_<binary_name>.csv
            matches = glob.glob(os.path.join("stageBlibs", "**", f"packages_{binary_name}.csv"), recursive=True)
            if matches:
                pkgs_csv = matches[0]

    print(f"[Stage C] Using Stage B output: {pkgs_csv}")
    if not os.path.exists(pkgs_csv):
        print("[Stage C] ERROR: Stage B output not found.")
        print("Hint: run Stage A and Stage B with the SAME binary path first.")
        sys.exit(2)

    # Stage C output path (always inside repo)
    REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    out_dir = os.path.join(REPO_ROOT, "stageCCve", tool_name)
    os.makedirs(out_dir, exist_ok=True)
    out_csv = os.path.join(out_dir, f"cves_{binary_name}.csv")
    print(f"[Stage C] Output will be: {out_csv}")

    # Peek a couple rows from Stage B
    with open(pkgs_csv, newline="") as f:
        rr = csv.reader(f)
        for i, row in enumerate(rr):
            print("[peek]", row)
            if i == 2:
                break

    # Build resolved_packages from Stage B (normalize to name:major.minor)
    resolved_packages = []
    with open(pkgs_csv, newline="") as f:
        r = csv.DictReader(f)
        for row in r:
            if row.get("Status", "").lower() != "resolved":
                continue
            bp = (row.get("BinaryPackage", "") or "").strip()
            vo = (row.get("VersionOnly", "") or "").strip()

            if not bp:
                continue

            if ":" in bp:
                # dpkg format "<pkg>:<full-version>" -> <pkg>:<major.minor> via VersionOnly
                name = bp.split(":", 1)[0].lower()
                m = re.search(r"\d+\.\d+", vo)
                ver = (m.group(0) if m else vo).lower()
                norm = f"{name}:{ver}" if name and ver else ""
            else:
                # rpm format "name-version-release.arch" -> use helper
                norm = normalize_package_name(bp)

            if norm:
                resolved_packages.append(norm)

    resolved_packages = sorted(set(resolved_packages))
    print(f"[Stage C] Packages loaded: {len(resolved_packages)}")

    # Find CVE JSON files under the given root (FULL TREE)
    pattern = os.path.join(cvelist_root, "cves", "*", "*", "CVE-*.json")
    cve_files = glob.glob(pattern, recursive=True)
    print(f"[Stage C] CVE files scanned: {len(cve_files)}")

    # Collect results: only append relevant rows (keeps CSV small)
    results = []
    for path in cve_files:
        try:
            with open(path, "r", encoding="utf-8") as fp:
                data = json.load(fp)
        except Exception:
            continue

        meta = extract_metadata(data)
        title = extract_title(data)
        desc  = extract_description(data)
        cvss  = extract_cvss_score(data)
        cwe   = extract_cwe(data)
        refs  = extract_references(data)
        aff   = extract_affected(data)
        probs = extract_problem_types(data)

        for pkg in resolved_packages:
            if is_cve_relevant(data, [pkg], debug=False):
                results.append({
                    "resolved_package": pkg,
                    "cve_id": meta["cve_id"],
                    "published_date": meta["published_date"],
                    "title": title,
                    "description": desc,
                    "cvss_score": cvss,
                    "cwe": cwe,
                    "problem_types": probs,
                    "references": refs,
                    "affected": aff,
                    "relevant": True
                })

    write_stagec_output_to_csv_with_resolved_packages(results, output_file=out_csv)
    print(f"[Stage C] Relevant matches: {len(results)}")
    print(f"[Stage C] Done -> {out_csv}")
