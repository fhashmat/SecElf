# ---------------------------------------------------------------
# stage_a3_obfuscated_function_categorizer.py
#
# Context:
#   Stage A3 will analyze extracted functions from Stage A2
#   and attempt to categorize whether they appear obfuscated,
#   crypto-related, or cleartext, using simple heuristics.
#
# Flow:
#   1. Read functions_stageA2.csv
#   2. Apply heuristics to guess obfuscation category
#   3. Save categorized results in functions_stageA3_obfuscated.csv
#
# ---------------------------------------------------------------

import csv
import re

# ---------------------------------------------------------------
# categorize_function()
#
# Description:
#   Takes a function name (demangled) and returns an
#   obfuscation category.
#
# Inputs:
#   func_name (str) - demangled function name
#
# Returns:
#   category (str): one of "cleartext", "mangled",
#   "crypto-related", "suspicious", "unknown"
# ---------------------------------------------------------------
def categorize_function(func_name):
    lowered = func_name.lower()
    
    # crude heuristic: C++ mangled names usually start with _Z
    if func_name.startswith("_Z"):
        return "mangled"
    
    # look for crypto/hashing keywords
    crypto_keywords = ["sha", "aes", "des", "md5", "encrypt", "decrypt", "hmac"]
    if any(keyword in lowered for keyword in crypto_keywords):
        return "crypto-related"
    
    # look for very short or weird names
    if len(func_name) <= 2:
        return "suspicious"
    
    # fallback
    return "cleartext"

# ---------------------------------------------------------------
# write_categorized_obfuscated_functions()
#
# Description:
#   Writes the list of obfuscated functions with their assigned
#   categories to a CSV file for further review.
#
# Inputs:
#   obfuscated_functions (list of dicts) - output of categorizer
#   output_file (str) - name of the CSV file
#
# Returns:
#   None (writes file to disk)
# ---------------------------------------------------------------
def write_categorized_obfuscated_functions(obfuscated_functions, output_file="stagea3_obfuscated_functions.csv"):
    import csv
    with open(output_file, "w", newline="") as f:
        writer = csv.writer(f)
        
        # Write CSV header
        writer.writerow([
            "FunctionName",
            "ObfuscationCategory"
        ])

        # Write function rows
        for func in obfuscated_functions:
            writer.writerow([
                func["FunctionName"],
                func["obfuscation_category"]
            ])
    print(f"Wrote categorized obfuscated functions to {output_file}")


# ---------------------------------------------------------------
# placeholder_obfuscated_function_categorizer()
#
# Description:
#   This placeholder function simulates analyzing the
#   demangled functions from Stage A2 and assigns a
#   basic obfuscation category.
#
# Inputs:
#   functions (list of dicts) - functions extracted from Stage A2
#
# Returns:
#   list of dicts with an added "obfuscation_category" key
# ---------------------------------------------------------------

def placeholder_ghidra_obfuscated_function_categorizer(functions):
    """
    Dummy placeholder categorizer — assigns 'Unknown' for now
    until proper Ghidra or ML-based classifiers are built.
    """
    for func in functions:
        func["obfuscation_category"] = "Unknown"
    return functions
 