# ---------------------------------------------------------------
# SecElf Stage A Testbench (Test Suite)
#
# Description:
#   This file acts as a testbench for validating the Stage A
#   functionality of the SecElf tool. Each unit test corresponds
#   to a key function, and is numbered for traceability.
#
# Tests included:
#   1. test_stage_a_process_runs_without_crashing
#   2. test_extract_strings_returns_nonempty_list
#   3. test_extract_symbols_returns_main_symbol
#   4. test_extract_libraries_returns_list
#
# Usage:
#   Run with:
#     PYTHONPATH=src python3 -m pytest
#
# Notes:
#   - Pytest automatically collects functions prefixed with 'test_'
#   - Green dots (.) indicate passing tests
#   - Red F's indicate failing tests
# ---------------------------------------------------------------


import pytest
from elftools.elf.elffile import ELFFile
from secelf import stage_a
from secelf.stage_a import (
    extract_strings,
    extract_symbols,
    extract_libraries_from_dynamic,
    combine_stage_a_data
)
import os  # for testing CSV output


# ---------------------------------------------------------------
# Test: stage_a_process runs successfully
#
# This test verifies that the high-level orchestration function
# does not crash on a minimal ELF binary. It is a smoke test
# to ensure Stage A wiring is functional.
# ---------------------------------------------------------------

def test_1_stage_a_process_runs_without_crashing():
    test_binary = "tests/fixtures/dummy_binary"
    try:
        stage_a.stage_a_process(test_binary)
    except FileNotFoundError:
        pytest.skip("dummy ELF binary not present yet")
    except Exception as e:
        pytest.fail(f"stage_a_process raised an unexpected exception: {e}")
# ---------------------------------------------------------------
# Test: extract_strings returns expected output
#
# This test verifies that extract_strings() can successfully
# pull printable ASCII strings from the .rodata section of
# a known ELF. The string "Hello" is expected because the
# test binary is a simple hello-world program.
# ---------------------------------------------------------------

def test_2_extract_strings_returns_nonempty_list():
    """
    Tests that extract_strings returns a non-empty list from the dummy binary.
    """
    with open("tests/fixtures/dummy_binary", "rb") as f:
        elf_file = ELFFile(f)
        result = extract_strings(elf_file)
        assert isinstance(result, list)
        assert any("Hello" in s for s in result)  # because our hello.c binary prints "Hello"
from secelf.stage_a import extract_symbols

# ---------------------------------------------------------------
# Test: extract_symbols returns expected symbols
#
# This test verifies that extract_symbols() can successfully
# identify symbol names from the .dynsym or .symtab sections.
# We expect at least 'main' in a typical hello-world ELF.
# ---------------------------------------------------------------
def test_3_extract_symbols_returns_main_symbol():
    symbols = extract_symbols("tests/fixtures/dummy_binary")
    assert isinstance(symbols, list)
    assert any("main" in s for s in symbols), "Expected to find 'main' in symbol list"

# ---------------------------------------------------------------
# Test: extract_libraries_from_dynamic returns a list
#
# This test verifies that extract_libraries_from_dynamic() correctly
# parses the .dynamic section, even if no DT_NEEDED entries are present.
# ---------------------------------------------------------------
def test_4_extract_libraries_returns_list():
    with open("tests/fixtures/dummy_binary", "rb") as f:
        elf_file = ELFFile(f)
        libraries = extract_libraries_from_dynamic(elf_file)
        assert isinstance(libraries, list)
