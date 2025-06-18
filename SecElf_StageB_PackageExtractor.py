import subprocess #This is for rpm (red hat package manager tool which we will be using in this to access the package name of the libraries)
import csv #This is for parsing results in csv and accessing the csv of the SecElf_StageA_BinAnalysis

#The following code is for accessing the previous csv from SecElf_StageA_BinAnalysis.
#Here we are accessing only the library column from the csv using the DictReader command which can access any specificed column of the csv.
#We have set the value of the row.get to the column name which is "Library" to get the required library data.
results = {}  # Dictionary to store library path -> package info
with open("elfdata_combined.csv", "r") as f:
    reader = csv.DictReader(f)
    for row in reader:
        library = row.get("LibraryPath", "")  # Note for myself: It can be replaced with any column of your choice for future use. 
        if library:
            print("Processing:", library)

            FORMAT = "%{NAME},%{VERSION}\n" #This is the output format for the rpm query, showing package name and version only

            #The following try block is used to handle errors if the library is not found in the rpm database.
            #If not found, it simply sets result to empty and skips printing.
            try:
                result = subprocess.check_output(['rpm', '--qf', FORMAT, '-qf', library]) #This runs the rpm command to find the package info for the given library file
                results[library] = " ".join(result.decode().strip().split(","))
            except:
                result = b"" #If rpm fails (file not from any package), we just use empty value
                results[library] = ""

            print("Package Info:", result.decode().strip()) #This prints the final result (decoded from bytes to string) if found

# BELOW CODE IS FOR STORING LIBRARY NAME AND ITS PACKAGE VERSION INTO NEW CSV FILE
# This code writes the resolved package info (e.g., glibc 2.28) into a separate CSV for each library

with open("library_packages.csv", "w", newline="") as out_file:
    writer = csv.writer(out_file)
    writer.writerow(["LibraryPath", "ResolvedPackage"])  # Column headers
    for lib, pkg in results.items():
        writer.writerow([lib, pkg])





