# ---------------------------------------------------------------
# test_stagea_strings.py
#
# SecElf Stage A Strings Testbench
#
# Description:
#   Tests the dedicated Stage A Strings extraction module.
#   Includes orchestration + helper tests.
#
# Usage:
#   PYTHONPATH=src python3 -m pytest tests/test_stagea_strings.py
#
# Notes:
#   Green dots = passing
#   Red F's    = failure
# How to Run? PYTHONPATH=src python3 -m pytest tests/test_stagea_strings.py
# ---------------------------------------------------------------

import pytest
from elftools.elf.elffile import ELFFile
from secelf import stage_a_strings
import os
import csv

# ---------------------------------------------------------------
# Test 1: stage_a_strings_process runs successfully
#
# Verifies that the orchestration runs without errors
# and generates the expected CSV.
# ---------------------------------------------------------------
def test_1_stage_a_strings_process_creates_csv():
    test_binary = "tests/fixtures/dummy_binary"
    try:
        stage_a_strings.stage_a_strings_process(test_binary)
    except FileNotFoundError:
        pytest.skip("dummy ELF binary not present")
    except Exception as e:
        pytest.fail(f"stage_a_strings_process raised: {e}")

    # check file exists
    assert os.path.exists("stagea_strings.csv")

# ---------------------------------------------------------------
# Test 2: extract_strings returns a nonempty list
#
# Verifies that .rodata strings are extracted.
# ---------------------------------------------------------------
def test_2_extract_strings_nonempty_list():
    with open("tests/fixtures/dummy_binary", "rb") as f:
        elf_file = ELFFile(f)
        strings = stage_a_strings.extract_strings(elf_file)
        assert isinstance(strings, list)
        assert any("Hello" in s for s in strings)

# ---------------------------------------------------------------
# Test 3: check CSV contents
#
# Confirms that the generated CSV actually contains
# the expected string "Hello" from the test binary.
# ---------------------------------------------------------------
def test_3_strings_csv_contains_hello():
    with open("stagea_strings.csv", "r") as f:
        reader = csv.reader(f)
        rows = list(reader)
        # skip header
        data_rows = rows[1:]
        found = any("Hello" in row[0] for row in data_rows)
        assert found, "CSV did not contain expected string 'Hello'"
