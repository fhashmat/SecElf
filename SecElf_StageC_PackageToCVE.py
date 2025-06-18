import csv              # For reading and writing CSV files
import requests         # For making HTTP requests to APIs/websites
import time             # For sleep/delay to avoid rate limits
import re               # For basic regex parsing

# -----------------------------------------------------------------------------
# Stage C: Package to CVE Mapping (SecElf_StageC_PackageToCVE.py)
#
# Algorithm Steps:
#
# 1. Read input from 'library_packages.csv' containing: we only need to read one column here which contains the resolved package without commas                                                                                                                 
#    - package_name
#    - package_version
#Accessing the resolved package column from the stage B
#This code is also normalizing
resolved_packages = [] # created an empty list to store all the resolved packages got from the stage B column resolved packages
with open("library_packages.csv", "r") as f: # Open the Stage B CSV file 
    reader = csv.DictReader(f) #Use DictReader to read the CSV specific column
    for row in reader: # Loop through each row in the csv file
        resolved = row.get("ResolvedPackage", "").strip() # remove any leading or trailing spaces
        if resolved: #just storing the values of resolved packages if they are present
            resolved_packages.append(resolved.lower())


# FOR NOW THIS PART COULD BE SKIPPED. LATER IF WE NEED TO NORMALIZE MORE WE CAN DEFINE A FUNCTION HERE.
# 2. Normalize package names and versions if necessary:
#    - Convert package names to lowercase
#    - Optionally strip distribution-specific suffixes from version strings
#if the package version = 1.1.1f-1ubuntu2.16" it will convert it to 1.1.1f"
#if the package version is package_version = "1.2.8" then it will remain like 1.2.8"



#
# 3. For each (resolved package) entry: 
# In this we will be working on the NVD database only for now. 
#    a. Query the NVD API using package name and version
#       - Extract CVE ID, CVSS score, description, and reference URL (URL is not required for now)
#



#    b. Scrape the Debian Security Tracker for the source package
#       - Match the version and extract listed CVEs
#    c. Scrape CVEDetails for matching product and version
#       - Parse CVE table to extract relevant vulnerability details
#
# 4. For each discovered CVE, write an entry to 'package_cves.csv' with:
#    - package_name
#    - package_version
#    - cve_id
#    - cvss_score
#    - description
#    - source_url (Not Required for now)
#
# 5. Log progress and handle exceptions:
#    - Respect rate limits and retry on request failures
#    - Log number of CVEs found per package
# -----------------------------------------------------------------------------

