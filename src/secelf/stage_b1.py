#!/usr/bin/env python3

# stage_b1.py
# Stage B1: Dependency Risk Metadata Enrichment
#
# Purpose:
#   Read Stage B package-resolution output and enrich each resolved dependency
#   with metadata needed for Table 2 and later CVE analysis.
#
# Input:
#   outputs/stageB/<tool_version>/packages_<tool>.csv
#
# Output:
#   outputs/stageB1/<tool_version>/dependency_risk_metadata.csv
#
# Planned columns:
#   Tool
#   Version
#   BinaryPackage
#   SourcePackage
#   UpstreamProject
#   VersionOnly
#   LibraryCategory
#   Maintainer
#   OldestUpdate

import csv
import os
import re
import subprocess
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime


def clean_package_name(pkg_name):
    """
    Remove version suffix from a package string.

    Example:
        libc6:2.35-0ubuntu3.13 -> libc6
        zlib1g:1:1.2.11.dfsg-2ubuntu9.2 -> zlib1g
    """
    if not pkg_name:
        return ""
    return pkg_name.split(":")[0].strip()


def infer_upstream_project(binary_package, source_package):
    """
    Choose the best project identity for downstream CVE matching.

    Priority:
        1. SourcePackage if available
        2. BinaryPackage otherwise

    Then normalize a few common package names into cleaner upstream labels.
    """
    base = source_package if source_package else binary_package
    base = clean_package_name(base).lower()

    normalization_map = {
        "zlib1g": "zlib",
        "libc6": "glibc",
        "libncurses5": "ncurses",
        "libtinfo5": "ncurses",
        "libexpat1": "expat",
        "libdbus-1-3": "dbus",
        "libgpg-error0": "libgpg-error",
        "libkeyutils1": "keyutils",
        "liblzma5": "xz",
        "libcap2": "libcap",
        "libcom-err2": "e2fsprogs",
    }

    return normalization_map.get(base, base)


def categorize_library(upstream_project):
    """
    Assign a coarse library category for summary-table use.
    This is heuristic and can be refined later.
    """
    project = (upstream_project or "").lower()

    if any(x in project for x in ["ssl", "crypto", "gpg", "keyutils"]):
        return "Crypto/Security"
    if any(x in project for x in ["zlib", "xz", "lzma"]):
        return "Compression"
    if any(x in project for x in ["glibc", "libc", "ncurses", "libcap", "e2fsprogs"]):
        return "System/Core"
    if any(x in project for x in ["dbus"]):
        return "IPC/System Services"
    if any(x in project for x in ["expat", "xml"]):
        return "Parsing"
    return "Other"


def get_package_maintainer(pkg_name):
    """
    Extract Maintainer field from dpkg metadata if available.
    Returns empty string if unavailable.
    """
    pkg = clean_package_name(pkg_name)
    if not pkg:
        return ""

    try:
        result = subprocess.run(
            ["dpkg-query", "-s", pkg],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )
        for line in result.stdout.splitlines():
            if line.startswith("Maintainer:"):
                return line.split(":", 1)[1].strip()
    except Exception:
        pass

    return ""


def get_latest_update(pkg_name):
    """
    Extract the most recent package changelog date from
    /usr/share/doc/<package>/changelog.Debian.gz.

    Why:
        apt-cache show gives version and maintainer, but not a useful update date.
        Debian/Ubuntu changelogs usually store maintainer entries with dates.

    Returns:
        A date string from the first changelog entry if available.
        Empty string otherwise.
    """
    pkg = clean_package_name(pkg_name)
    if not pkg:
        return ""

    changelog_path = f"/usr/share/doc/{pkg}/changelog.Debian.gz"

    try:
        result = subprocess.run(
            ["zgrep", "-m", "1", "^ -- ", changelog_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )

        line = result.stdout.strip()
        if not line:
            return ""

        # Example line:
        # -- Nishit Majithia <...>  Fri, 30 Jan 2026 13:50:56 +0530
        parts = line.split("  ")
        if len(parts) >= 2:
            return parts[-1].strip()

    except Exception:
        pass

    return ""

def extract_year(date_str):
    """
    Extract year from a changelog date string.

    Example:
        "Fri, 14 Oct 2022 18:33:00 -0300" -> 2022
    """
    if not date_str:
        return None
    try:
        dt = parsedate_to_datetime(date_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.year
    except Exception:
        return None


def summarize_shared_metadata(enriched_rows, outdated_before_year=2024):
    """
    Build one summary row for the shared-library side of Table 2.

    We summarize by unique upstream project, not by duplicated package rows.
    """
    unique_projects = {}
    for row in enriched_rows:
        proj = row["UpstreamProject"]
        if proj not in unique_projects:
            unique_projects[proj] = row

    # Unique categories
    categories = sorted({
        row["LibraryCategory"]
        for row in unique_projects.values()
        if row["LibraryCategory"]
    })

    # Unique maintainers
    maintainers = sorted({
        row["Maintainer"]
        for row in unique_projects.values()
        if row["Maintainer"]
    })

    # Outdated projects: latest observed update year < cutoff
    outdated_years = []
    for row in unique_projects.values():
        yr = extract_year(row["LatestUpdate"])
        if yr is not None and yr < outdated_before_year:
            outdated_years.append(yr)

    return {
        "SharedLibraryCategory": "; ".join(categories) if categories else "",
        "SharedPackageMaintainer": "; ".join(maintainers) if maintainers else "",
        "SharedOutdatedDependencyCount": len(outdated_years),
        "OldestOutdatedDependencyUpdateYear": min(outdated_years) if outdated_years else "N/A",
    }

def load_stageb_rows(csv_path):
    """
    Load only resolved Stage B rows.

    Ignores:
        - unresolved rows
        - empty package rows
        - obvious noisy placeholders such as texlive-lang-german from MISSING
    """
    rows = []

    with open(csv_path, "r", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            status = (row.get("Status") or "").strip()
            binary_package = (row.get("BinaryPackage") or "").strip()

            if status != "Resolved":
                continue
            if not binary_package:
                continue
            if binary_package.startswith("texlive-lang-german"):
                continue

            rows.append(row)

    return rows
def write_b1_output(rows, output_csv):
    """
    Write enriched dependency metadata rows to CSV.
    """
    fieldnames = [
        "Tool",
        "Version",
        "BinaryPackage",
        "SourcePackage",
        "UpstreamProject",
        "VersionOnly",
        "LibraryCategory",
        "Maintainer",
        "LatestUpdate",
    ]

    os.makedirs(os.path.dirname(output_csv), exist_ok=True)

    with open(output_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

def write_b1_summary(tool, version, enriched_rows, output_csv):
    """
    Write one shared-library summary row for Table 2.
    """

    summary = summarize_shared_metadata(enriched_rows, outdated_before_year=2024)

    row = {
        "Tool": tool,
        "Version": version,
        "SharedLibraryCategory": summary["SharedLibraryCategory"],
        "SharedPackageMaintainer": summary["SharedPackageMaintainer"],
        "SharedOutdatedDependencyCount": summary["SharedOutdatedDependencyCount"],
        "OldestOutdatedDependencyUpdateYear": summary["OldestOutdatedDependencyUpdateYear"],
    }

    fieldnames = [
        "Tool",
        "Version",
        "SharedLibraryCategory",
        "SharedPackageMaintainer",
        "SharedOutdatedDependencyCount",
        "OldestOutdatedDependencyUpdateYear",
    ]

    with open(output_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerow(row)

def stage_b1_process(tool, version, stageb_csv_path):
    """
    Main Stage B1 routine.

    Input:
        One Stage B CSV for one tool/version.

    Output:
        outputs/stageB1/<tool_version>/dependency_risk_metadata.csv
    """
    stageb_rows = load_stageb_rows(stageb_csv_path)
    enriched_rows = []

    for row in stageb_rows:
        binary_package = (row.get("BinaryPackage") or "").strip()
        source_package = (row.get("SourcePackage") or "").strip()
        version_only = (row.get("VersionOnly") or "").strip()

        upstream_project = infer_upstream_project(binary_package, source_package)
        library_category = categorize_library(upstream_project)
        maintainer = get_package_maintainer(binary_package or source_package)
        oldest_update = get_latest_update(binary_package or source_package)

        enriched_rows.append({
            "Tool": tool,
            "Version": version,
            "BinaryPackage": binary_package,
            "SourcePackage": source_package,
            "UpstreamProject": upstream_project,
            "VersionOnly": version_only,
            "LibraryCategory": library_category,
            "Maintainer": maintainer,
            "LatestUpdate": oldest_update,
        })

    output_dir = os.path.join(
        "outputs",
        "stageB1",
        f"{tool.lower()}_{version.replace('.', '_')}"
    )
    output_csv = os.path.join(output_dir, "dependency_risk_metadata.csv")

    write_b1_output(enriched_rows, output_csv)
    summary_csv = os.path.join(output_dir, "shared_dependency_summary.csv")
    write_b1_summary(tool, version, enriched_rows, summary_csv)
    print(f"[OK] Wrote Stage B1 output to: {output_csv}")