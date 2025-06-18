import csv              # For reading and writing CSV files
import requests         # For making HTTP requests to APIs/websites
import time             # For sleep/delay to avoid rate limits
import re               # For basic regex parsing

# -----------------------------------------------------------------------------
# Stage C: Package to CVE Mapping (SecElf_StageC_PackageToCVE.py)
#
# Algorithm Steps:
#
# 1. Read input from 'library_packages.csv' containing:
#    - library_path
#    - package_name
#    - package_version
#
# 2. Normalize package names and versions if necessary:
#    - Convert package names to lowercase
#    - Optionally strip distribution-specific suffixes from version strings
#
# 3. For each (package_name, package_version) entry:
#    a. Query the NVD API using package name and version
#       - Extract CVE ID, CVSS score, description, and reference URL
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
#    - source_url
#
# 5. Log progress and handle exceptions:
#    - Respect rate limits and retry on request failures
#    - Log number of CVEs found per package
# -----------------------------------------------------------------------------

