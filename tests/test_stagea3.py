# ---------------------------------------------------------------
# SecElf Stage A3 Testbench
#
# This verifies that the obfuscation categorizer runs correctly
# on a small sample CSV of functions.
#
# Usage:
#   PYTHONPATH=src python3 -m pytest
# ---------------------------------------------------------------

import csv
import pytest
from secelf.stage_a3_obfuscated_function_categorizer import categorize_function

def test_stagea3_categorizer_classifies_correctly():
    """
    Test 1: Check that the categorizer assigns the expected
    categories to demo functions.
    """
    sample_functions = [
        {"name": "_ZN3fooEv"},
        {"name": "encrypt_block"},
        {"name": "x"}
    ]

    results = []
    for func in sample_functions:
        cat = categorize_function(func["name"])
        results.append(cat)

    assert results[0] == "mangled"
    assert results[1] == "crypto-related"
    assert results[2] == "suspicious"
