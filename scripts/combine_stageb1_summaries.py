#!/usr/bin/env python3

# combine_stageb1_summaries.py
# Combine per-tool Stage B1 shared dependency summary files into one CSV.

import csv
import glob
import os


def main():
    files = sorted(glob.glob("outputs/stageB1/*/shared_dependency_summary.csv"))
    out = "outputs/stageB1/all_shared_dependency_summaries.csv"

    rows = []
    for f in files:
        with open(f, newline="", errors="ignore") as fh:
            reader = csv.DictReader(fh)
            rows.extend(list(reader))

    os.makedirs(os.path.dirname(out), exist_ok=True)

    with open(out, "w", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "Tool",
                "Version",
                "SharedLibraryCategory",
                "SharedPackageMaintainer",
                "SharedOutdatedDependencyCount",
                "OldestOutdatedDependencyUpdateYear",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"[OK] Wrote: {out}")


if __name__ == "__main__":
    main()