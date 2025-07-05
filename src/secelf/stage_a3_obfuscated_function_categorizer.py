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
