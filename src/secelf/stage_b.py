import subprocess  # This is for rpm and dpkg package manager tools
import csv         # This is for parsing results in csv and accessing the csv of the SecElf_StageA_BinAnalysis
import sys         # For accessing command-line arguments
import os

# TO RUN: PYTHONPATH=src python3 src/secelf/stage_b.py lib_analysis_dummy_binary.csv
#PYTHONPATH=src python3 src/secelf/stage_b.py /path/to/dummy_binary



# The following helper function gets both binary and source package info for a given library path.
# It tries rpm first (Red Hat), and falls back to dpkg (Debian/Ubuntu) if rpm fails.
def get_package_info(library_path):
    """
    Given a library path, returns a tuple:
    (binary_package_name_with_version, source_package_name)
    Uses rpm first, falls back to dpkg with version info.
    """
    binary_pkg = ""
    source_pkg = ""

    try:
        # Try RPM first (for Red Hat-based systems)
        binary_pkg = subprocess.check_output(
            ['rpm', '--qf', '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}', '-qf', library_path],
            stderr=subprocess.DEVNULL
        ).decode().strip()

        source_pkg = subprocess.check_output(
            ['rpm', '--qf', '%{SOURCERPM}', '-qf', library_path],
            stderr=subprocess.DEVNULL
        ).decode().strip()

    except:
        try:
            # Fallback to dpkg -S (for Debian-based systems)
            dpkg_output = subprocess.check_output(
                ['dpkg', '-S', library_path],
                stderr=subprocess.DEVNULL
            ).decode().strip()

            pkg_name = dpkg_output.split(":")[0].strip()

            # Now get version info using dpkg -s
            dpkg_status = subprocess.check_output(
                ['dpkg', '-s', pkg_name],
                stderr=subprocess.DEVNULL
            ).decode().strip()

            version_line = [line for line in dpkg_status.split('\n') if line.startswith("Version:")]
            version = version_line[0].split(":", 1)[1].strip() if version_line else ""

            binary_pkg = f"{pkg_name}:{version}"
            source_pkg = ""  # dpkg doesn't expose source package names

        except:
            pass

    return binary_pkg, source_pkg



# The following code is for accessing the previous csv from SecElf_StageA_BinAnalysis.
# Here we are accessing only the "Resolved Path (ldd)" column from the csv using the DictReader command
# which can access any specified column of the csv.
results = {}  # Dictionary to store library path -> (binary_pkg, source_pkg)
# Derive input CSV name from binary path (same logic as Stage A)
if len(sys.argv) < 2:
    print("Usage: python stage_b.py <binary_path>")
    sys.exit(1)

binary_path = sys.argv[1]
binary_name = os.path.basename(binary_path)
tool_name = os.path.splitext(binary_name)[0]  # e.g., "genus" from "genus"
input_csv = os.path.join("stageAlibs", tool_name, f"lib_analysis_{binary_name}.csv")

with open(input_csv, "r") as f:
    reader = csv.DictReader(f)
    for row in reader:
        library = row.get("Resolved Path (ldd)", "").strip()
        # Note for myself: It can be replaced with any column of your choice for future use.
        if library:
            print("Processing:", library)

            # The following block now calls our helper to get both binary and source packages
            binary_pkg, source_pkg = get_package_info(library)
            results[library] = (binary_pkg, source_pkg)

            print("Binary Package:", binary_pkg)
            print("Source Package:", source_pkg)

# BELOW CODE IS FOR STORING LIBRARY NAME AND ITS PACKAGE VERSION INTO NEW CSV FILE
# Output now goes under stageBlibs/<tool_name>/packages_<binary_name>.csv
out_dir = os.path.join("stageBlibs", tool_name)
os.makedirs(out_dir, exist_ok=True)
output_csv = os.path.join(out_dir, f"packages_{binary_name}.csv")

with open(output_csv, "w", newline="") as out_file:
    writer = csv.writer(out_file)
    writer.writerow(["LibraryPath", "BinaryPackage", "SourcePackage", "VersionOnly", "Status"])  # Added Status column
    for lib, (binpkg, srcpkg) in results.items():
        version = ""
        if binpkg:
            if ":" in binpkg:  # dpkg format
                version = binpkg.split(":", 1)[1]
            elif "-" in binpkg:  # rpm format
                parts = binpkg.split("-")
                if len(parts) >= 2:
                    version = parts[1]

        status = "Resolved" if binpkg else "Unresolved"
        writer.writerow([lib, binpkg, srcpkg, version, status])

print(f"[Stage B] Wrote output to: {output_csv}")


