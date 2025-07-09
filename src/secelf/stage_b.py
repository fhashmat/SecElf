import subprocess  # This is for rpm (Red Hat package manager tool which we will be using in this to access the package name of the libraries)
import csv  # This is for parsing results in csv and accessing the csv of the SecElf_StageA_BinAnalysis
import sys

# TO RUN PYTHONPATH=src python3 src/secelf/stage_b.py lib_analysis_dummy_binary.csv


# The following helper function gets both binary and source package info for a given library path.
def get_package_info(library_path):
    """
    Given a library path, returns a tuple:
    (binary_package_name, source_package_name)
    """
    binary_pkg = ""
    source_pkg = ""

    try:
        binary_pkg = subprocess.check_output(
            ['rpm', '--qf', '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}', '-qf', library_path],
            stderr=subprocess.DEVNULL
        ).decode().strip()
    except:
        pass

    try:
        source_pkg = subprocess.check_output(
            ['rpm', '--qf', '%{SOURCERPM}', '-qf', library_path],
            stderr=subprocess.DEVNULL
        ).decode().strip()
    except:
        pass

    return binary_pkg, source_pkg


# The following code is for accessing the previous csv from SecElf_StageA_BinAnalysis.
# Here we are accessing only the library column from the csv using the DictReader command which can access any specified column of the csv.
# We have set the value of the row.get to the column name which is "LibraryPath" to get the required library data.
results = {}  # Dictionary to store library path -> (binary_pkg, source_pkg)
input_csv = sys.argv[1] if len(sys.argv) > 1 else "lib_analysis_dummy_binary.csv"
with open(input_csv, "r") as f:
    reader = csv.DictReader(f)
    for row in reader:
        library = row.get("LibraryPath", "")  # Note for myself: It can be replaced with any column of your choice for future use. 
        if library:
            print("Processing:", library)

            # The following block now calls our helper to get both binary and source packages
            binary_pkg, source_pkg = get_package_info(library)
            results[library] = (binary_pkg, source_pkg)

            print("Binary Package:", binary_pkg)
            print("Source Package:", source_pkg)

# BELOW CODE IS FOR STORING LIBRARY NAME AND ITS PACKAGE VERSION INTO NEW CSV FILE
# This code writes the resolved package info (e.g., glibc 2.28) into a separate CSV for each library
with open("library_packages.csv", "w", newline="") as out_file:
    writer = csv.writer(out_file)
    writer.writerow(["LibraryPath", "BinaryPackage", "SourcePackage"])  # Column headers
    for lib, (binpkg, srcpkg) in results.items():
        writer.writerow([lib, binpkg, srcpkg])


