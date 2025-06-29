# stage_b.py

import csv
import subprocess

def resolve_library_packages(input_csv="elfdata_combined.csv"):
    """
    Reads the given CSV, extracts the LibraryPath column, and queries rpm to
    resolve the package name and version for each library. Returns a dict.
    """
    results = {}
    with open(input_csv, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            library = row.get("LibraryPath", "")
            if library:
                print("Processing:", library)
                FORMAT = "%{NAME},%{VERSION}\n"
                try:
                    result = subprocess.check_output(['rpm', '--qf', FORMAT, '-qf', library])
                    results[library] = " ".join(result.decode().strip().split(","))
                except:
                    results[library] = ""
                print("Package Info:", results[library])
    return results


def write_resolved_packages(results, output_csv="library_packages.csv"):
    """
    Writes the resolved package info to a CSV file.
    """
    with open(output_csv, "w", newline="") as out_file:
        writer = csv.writer(out_file)
        writer.writerow(["LibraryPath", "ResolvedPackage"])
        for lib, pkg in results.items():
            writer.writerow([lib, pkg])

