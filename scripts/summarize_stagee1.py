#!/usr/bin/env python3

import os
import csv
import re

INPUT_ROOT = "outputs/stageE1"
OUTPUT_CSV = os.path.join(INPUT_ROOT, "stageE1_summary.csv")


def mark_present(path):
    """Return ● if file exists and is non-empty, else ◦."""
    return "●" if os.path.exists(path) and os.path.getsize(path) > 0 else "◦"


def parse_tool_version(folder_name):
    """
    Example:
        Genus_21_17 -> (Genus, 21.17)
        Innovus_21_12 -> (Innovus, 21.12)
        Assura_23_1_4_17 -> (Assura, 23.1.4.17)
    """
    parts = folder_name.split("_")
    tool = parts[0]
    version = ".".join(parts[1:])
    return tool, version


def privilege_mark(proc_status_path):
    """
    Mark ● only if there is evidence of elevated capabilities
    or runtime hardening flags in /proc/<pid>/status.
    Otherwise mark ◦.
    """
    if not os.path.exists(proc_status_path):
        return "◦"

    try:
        with open(proc_status_path, "r", errors="ignore") as f:
            text = f.read()

        capeff = re.search(r"CapEff:\s*([0-9a-fA-F]+)", text)
        capprm = re.search(r"CapPrm:\s*([0-9a-fA-F]+)", text)
        nonew = re.search(r"NoNewPrivs:\s*(\d+)", text)
        seccomp = re.search(r"Seccomp:\s*(\d+)", text)

        capeff_val = capeff.group(1) if capeff else "0"
        capprm_val = capprm.group(1) if capprm else "0"
        nonew_val = nonew.group(1) if nonew else "0"
        seccomp_val = seccomp.group(1) if seccomp else "0"

        if (
            capeff_val != "0000000000000000"
            or capprm_val != "0000000000000000"
            or nonew_val != "0"
            or seccomp_val != "0"
        ):
            return "●"

        return "◦"
    except Exception:
        return "◦"


def main():
    rows = []

    for name in sorted(os.listdir(INPUT_ROOT)):
        folder = os.path.join(INPUT_ROOT, name)
        if not os.path.isdir(folder):
            continue

        tool, version = parse_tool_version(name)

        row = {
            "Tool": tool,
            "Version": version,
            "ArtifactAccess": mark_present(os.path.join(folder, "artifact_access.txt")),
            "LogAccess": mark_present(os.path.join(folder, "log_access.txt")),
            "ConfigAccess": mark_present(os.path.join(folder, "config_access.txt")),
            "OtherAccess": mark_present(os.path.join(folder, "other_access.txt")),
            "ShellInvocation": mark_present(os.path.join(folder, "shell_invocation.txt")),
            "ExternalToolInvocation": mark_present(os.path.join(folder, "external_tools.txt")),
            "PrivilegeCapabilityEvidence": privilege_mark(os.path.join(folder, "proc_status.txt")),
            "HelpEvidence": mark_present(os.path.join(folder, "help.txt")),
        }

        rows.append(row)

    with open(OUTPUT_CSV, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "Tool",
                "Version",
                "ArtifactAccess",
                "LogAccess",
                "ConfigAccess",
                "OtherAccess",
                "ShellInvocation",
                "ExternalToolInvocation",
                "PrivilegeCapabilityEvidence",
                "HelpEvidence",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"[OK] Wrote Stage E1 summary to: {OUTPUT_CSV}")


if __name__ == "__main__":
    main()