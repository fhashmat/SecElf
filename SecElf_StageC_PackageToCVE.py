import csv              # For reading and writing CSV files
import requests         # For making HTTP requests to APIs/websites
import time             # For sleep/delay to avoid rate limits
import re               # For basic regex parsing
import json             #read and parse the JSON files
import os               #walking through directories with os.walk()

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

#resolved_packages = [] # created an empty list to store all the resolved packages got from the stage B column resolved packages
#with open("library_packages.csv", "r") as f: # Open the Stage B CSV file 
 #   reader = csv.DictReader(f) #Use DictReader to read the CSV specific column
  #  for row in reader: # Loop through each row in the csv file
   #     resolved = row.get("ResolvedPackage", "").strip() # remove any leading or trailing spaces
    #    if resolved: #just storing the values of resolved packages if they are present
     #       resolved_packages.append(resolved.lower())


# FOR NOW THIS PART COULD BE SKIPPED. LATER IF WE NEED TO NORMALIZE MORE WE CAN DEFINE A FUNCTION HERE.
# 2. Normalize package names and versions if necessary:
#    - Convert package names to lowercase
#    - Optionally strip distribution-specific suffixes from version strings
#if the package version = 1.1.1f-1ubuntu2.16" it will convert it to 1.1.1f"
#if the package version is package_version = "1.2.8" then it will remain like 1.2.8"


#This is the project we will using for getting the cve related information. https://github.com/CVEProject/cvelistV5
#cvelist5 is a Github based archive of all CVEs (Common Vulnerabilities and Exposures), maintained by the CVE project under MITRE.
#Structure is like as follows:
#cvelistV5/
    #cves/
        #2024/
            #CVE-2024-001.json
            #...
#schema/
    #cve_metadata_schema.json
        #...

#Every CVE is a JSON file with field like:
# CVE ID, datepublished, cna, affected, product, vendor, versions, version further status?, descriptions, metrics

#Feilds of interest from cvelistV5 JSON Structure:
#cveMetadata.cveID -> The CVE identifier (e.g., CVE-2024-0001)
# cveMetadata.datePublished       -> Date when the CVE was published
# containers.cna.title            -> Short title or summary of the issue
#containers.cna.descriptions     -> List of vulnerability descriptions (usually one in English)
# containers.cna.metrics          -> CVSS v2 / v3 scoring metrics (baseScore, vector, etc.)
# containers.cna.references       -> List of external reference URLs (NVD, vendor advisories, etc.)
#
# containers.cna.affected         -> List of affected software components:
#     - affected[].vendor         -> Name of the vendor (e.g., "openssl")
#     - affected[].product        -> Name of the product (e.g., "openssl")
#     - affected[].versions       -> List of version entries:
#         - versions[].version    -> Specific version string (e.g., "1.1.1f")
#         - versions[].status     -> Status (e.g., "affected", "unaffected", "under investigation")


#Function 1 extract_metadata: extract cve_id and published date
def extract_metadata(cve_json):
    meta = cve_json.get("cveMetadata", {})
    return {
        "cve_id": meta.get("cveId", ""),
        "published_date": meta.get("datePublished", "").split("T")[0]
    }

# Fucntion 2 extrac_title: 
def extract_title(cve_json):
    return cve_json.get("containers", {}).get("cna", {}).get("title", "")

# Function 3 Extract Description
def extract_description(cve_json):
    descriptions = cve_json.get("containers", {}).get("cna", {}).get("descriptions", [])
    for desc in descriptions:
        if desc.get("lang", "").lower().startswith("en"):
            return desc.get("value", "")
    return "No English description found"

# Function 4 extract_cvss_score
def extract_cvss_score(cve_json):
    metrics = cve_json.get("containers", {}).get("cna", {}).get("metrics", {})
    for version_key in ["cvssV31", "cvssV30", "cvssV2"]:
        if version_key in metrics:
            try:
                return metrics[version_key][0]["cvssData"]["baseScore"]
            except (IndexError, KeyError):
                continue
    return "N/A"

#Function 5 extract reference URLs (I can use these URLs while writing the paper as reference)
# -----------------------------------------------------------------------------
# Function: extract_references(cve_json)
#
# This function collects all external reference URLs from a CVE JSON entry.
# 
# 1. The CVE JSON structure includes a "containers" key, which contains a "cna"
#    dictionary. Inside that, there's a "references" list, where each item may
#    contain a "url" field pointing to a vendor advisory or security page.
#
# 2. The line:
#       refs = cve_json.get("containers", {}).get("cna", {}).get("references", [])
#    Safely walks through that structure. If any of the keys are missing,
#    it returns an empty list instead of throwing an error.
#
#    Example of what `refs` might look like:
#    [
#        {"url": "https://security-advisory.com/foo"},
#        {"url": "https://nvd.nist.gov/CVE-2024-xxxx"}
#    ]
#
# 3. The line:
#       urls = [ref.get("url", "") for ref in refs if "url" in ref]
#    Is a list comprehension that:
#      - Loops through each item in `refs`
#      - Extracts the value of the "url" key
#      - Skips any items that don't have a "url" key
#
# 4. The URLs are then joined using a semicolon (`; `) to form a single string
#    that fits nicely in a single CSV column.
#
# Example return value:
#   "https://security-advisory.com/foo; https://nvd.nist.gov/CVE-2024-xxxx"
# -----------------------------------------------------------------------------

def extract_references(cve_json):
    refs = cve_json.get("containers", {}).get("cna", {}).get("references", [])
    urls = [ref.get("url", "") for ref in refs if "url" in ref]
    return "; ".join(urls)


#Below is the Testing code for F1, F2,F3,F4 and F5.

test_cve_file = "cvelistV5/cves/2024/0xxx/CVE-2024-0250.json"

with open(test_cve_file, "r") as f:
    data = json.load(f)

print(">>> Metadata:", extract_metadata(data))
print(">>> Title:", extract_title(data))
print(">>> Description", extract_description(data))
print(">>> CVSS Score", extract_cvss_score(data))
print(">>> References:", extract_references(data))




