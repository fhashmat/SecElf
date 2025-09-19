# --- Stage C (SMOKE) --------------------------------------------------------
# Goal:
#   Match ONE package from a Stage-B CSV against ONE CVE JSON file and
#   write a tiny CSV with the result (if it matches).
#
# Usage:
#   PYTHONPATH=src python3 src/secelf/stage_c_smoke.py \
#       stageBlibs/smoke/packages_smoke.csv \
#       cvelist5temp/cves/1999/CVE-1999-0001.json
#
# Output:
#   stageCCve/smoke/cves_smoke.csv
# ---------------------------------------------------------------------------

import csv
import json
import os
import re
import sys

# --- Helpers ---------------------------------------------------------------

def normalize_package_name_rpm(pkg_name: str) -> str:
    """
    Turn an RPM-ish string like:
        'glibc-2.28-1.x86_64'
    into:
        'glibc:2.28'
    (drop arch, keep major.minor)
    """
    if not pkg_name:
        return ""
    # drop .arch suffix
    #That line removes the architecture suffix (.x86_64, .i686, .aarch64, .armv7hl) if the package name ends with it.
    pkg_name = re.sub(r"\.(x86_64|i686|aarch64|armv7hl)$", "", pkg_name)
    # capture name and major.minor
    m = re.match(r"^([A-Za-z0-9_+.\-]+)-(\d+\.\d+)", pkg_name)
    if not m:
        return pkg_name.lower()
    name = m.group(1).lower()
    ver  = m.group(2).lower()
    return f"{name}:{ver}"

def normalize_stageb_row(row: dict) -> str:
    """
    From a Stage-B row (BinaryPackage + VersionOnly), produce 'name:major.minor'.
    Handles rpm style and dpkg style ('name:fullversion').
    """
    bp = (row.get("BinaryPackage") or "").strip()
    vo = (row.get("VersionOnly") or "").strip()

    if not bp:
        return ""

    # dpkg: "name:fullversion"
    if ":" in bp:
        name = bp.split(":", 1)[0].lower()
        # try to take major.minor from VersionOnly (if present)
        m = re.search(r"\d+\.\d+", vo)
        ver = (m.group(0) if m else vo).lower()
        return f"{name}:{ver}" if (name and ver) else ""

    # rpm style
    return normalize_package_name_rpm(bp)

def load_cves(cve_path: str) -> list[dict]:
    with open(cve_path, "r", encoding="utf-8") as f:
        data = json.load(f)
        if isinstance(data, list):
            return data
        else:
            return [data]


def extract_first_english_description(cve: dict) -> str:
    try:
        descs = cve["containers"]["cna"].get("descriptions", [])
        for d in descs:
            if d.get("lang", "").lower().startswith("en"):
                return d.get("value", "")
    except Exception:
        pass
    return ""

def extract_cvss_base(cve: dict):
    try:
        metrics = cve["containers"]["cna"].get("metrics", [])
        for m in metrics:
            if "cvssV3_1" in m:
                return m["cvssV3_1"].get("baseScore", "")
    except Exception:
        pass
    return ""

def extract_problem_types(cve: dict) -> str:
    try:
        pts = cve["containers"]["cna"].get("problemTypes", [])
        out = []
        for pt in pts:
            for d in pt.get("descriptions", []):
                if "description" in d:
                    out.append(d["description"])
        return "; ".join(out)
    except Exception:
        return ""

def extract_cwe_quick(cve: dict) -> str:
    # sometimes problemTypes carry CWE labels; keep it simple
    try:
        pts = cve["containers"]["cna"].get("problemTypes", [])
        for pt in pts:
            for d in pt.get("descriptions", []):
                val = d.get("description", "")
                if "CWE-" in val:
                    return val
    except Exception:
        pass
    return ""

def extract_references(cve: dict) -> str:
    try:
        refs = cve["containers"]["cna"].get("references", [])
        urls = [r.get("url", "") for r in refs if r.get("url")]
        return "; ".join(urls)
    except Exception:
        return ""

def extract_affected_flat(cve: dict) -> list[tuple[str, str, str, str]]:
    """
    Return list of (vendor, product, version, status) from cna.affected[]
    """
    out = []
    try:
        affected = cve["containers"]["cna"].get("affected", [])
        for item in affected:
            vendor  = (item.get("vendor") or "").lower()
            product = (item.get("product") or item.get("packageName") or "").lower()
            for v in item.get("versions", []):
                ver    = (v.get("version") or "").lower()
                status = (v.get("status") or "").lower()
                out.append((vendor, product, ver, status))
    except Exception:
        pass
    return out

def cve_id_and_date(cve: dict) -> tuple[str, str]:
    meta = cve.get("cveMetadata", {})
    return meta.get("cveId", ""), (meta.get("datePublished", "") or "").split("T")[0]

# --- Matching (exact) ------------------------------------------------------

def matches(pkg_norm: str, affected: list[tuple[str, str, str, str]]) -> bool:
    if ":" not in pkg_norm:
        return False
    name, ver = pkg_norm.split(":", 1)
    for (_vendor, product, ver_cve, _status) in affected:
        # relax: substring match on product name
        if name in product or product in name:
            # relax: version check optional
            if ver in ver_cve or ver_cve.startswith(ver) or ver_cve == "" or ver_cve == "*":
                return True
    return False


# --- Main ------------------------------------------------------------------

def main():
    if len(sys.argv) < 3:
        print("Usage: PYTHONPATH=src python3 src/secelf/stage_c_full.py <stageB_tsv> <cve_dir> [out_csv]")
        sys.exit(1)

    stageb_csv = sys.argv[1]
    cve_dir    = sys.argv[2]
    out_csv    = sys.argv[3] if len(sys.argv) > 3 else "stageCCve/final_cves.csv"

    # 1) Load ALL resolved packages from Stage B
    packages = []
    with open(stageb_csv, newline="") as f:
        r = csv.DictReader(f, delimiter="\t")  # TSV not CSV
        for row in r:
            bp = (row.get("BINARY_PACKAGE") or "").strip()
            if not bp:
                continue
            pkg_norm = normalize_package_name_rpm(bp)
            if pkg_norm:
                packages.append(pkg_norm)

    if not packages:
        print("[WARN] No resolved packages found in Stage-B TSV.")
        sys.exit(0)

    print(f"[INFO] Loaded {len(packages)} resolved packages")

    # 2) Prepare output
    os.makedirs(os.path.dirname(out_csv), exist_ok=True)
    headers = [
        "ResolvedPackage", "CVE ID", "Published Date", "Title", "Description",
        "CVSS Score", "Problem Types", "CWE", "References", "Affected", "Relevant"
    ]
    with open(out_csv, "w", newline="") as f_out:
        w = csv.DictWriter(f_out, fieldnames=headers)
        w.writeheader()

        # 3) Walk CVE dir with progress counter
        count = 0
        for root, _, files in os.walk(cve_dir):
            for file in files:
                if not file.endswith(".json"):
                    continue
                count += 1
                if count % 1000 == 0:
                    print(f"[INFO] Processed {count} CVE files...")

                cve_path = os.path.join(root, file)
                with open(cve_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    # handle both dict and list
                    if isinstance(data, list):
                        cves = data
                    else:
                        cves = [data]

                for cve in cves:
                    affected = extract_affected_flat(cve)
                    cve_id, pub_date = cve_id_and_date(cve)

                for pkg_norm in packages:
                    if matches(pkg_norm, affected):
                        print(f"[MATCH] {pkg_norm} -> {cve_id}")  # <-- add this line
                        row = {
                            "ResolvedPackage": pkg_norm,
                            "CVE ID": cve_id,
                            "Published Date": pub_date,
                            "Title": (cve.get("containers", {}).get("cna", {}) or {}).get("title", ""),
                            "Description": extract_first_english_description(cve),
                            "CVSS Score": extract_cvss_base(cve),
                            "Problem Types": extract_problem_types(cve),
                            "CWE": extract_cwe_quick(cve),
                            "References": extract_references(cve),
                            "Affected": "; ".join([f"{a}:{p}:{v}:{s}" for (a,p,v,s) in affected]),
                            "Relevant": "Yes"
                        }
                        w.writerow(row)


    print(f"[DONE] Wrote: {out_csv}")


if __name__ == "__main__":
    main()
