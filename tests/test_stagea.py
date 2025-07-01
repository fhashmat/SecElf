# ---------------------------------------------------------------
# test_stagea.py
#
# Unit tests for Stage A functionality of SecElf.
#
# - Uses a known small ELF binary (tests/fixtures/dummy_binary)
# - Verifies:
#     * Stage A orchestration does not crash
#     * extract_strings() returns expected printable strings
#
# The pytest framework is used:
#   - Green lines = passing tests
#   - Red lines   = failing tests
#   - Pytest automatically collects functions prefixed with 'test_'
#
# Run with:
#   PYTHONPATH=src python3 -m pytest
# ---------------------------------------------------------------


import pytest
from secelf import stage_a
from secelf.stage_a import extract_strings
from elftools.elf.elffile import ELFFile

# ---------------------------------------------------------------
# Test: stage_a_process runs successfully
#
# This test verifies that the high-level orchestration function
# does not crash on a minimal ELF binary. It is a smoke test
# to ensure Stage A wiring is functional.
# ---------------------------------------------------------------

def test_stage_a_process_runs_without_crashing():
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

def test_extract_strings_returns_nonempty_list():
    """
    Tests that extract_strings returns a non-empty list from the dummy binary.
    """
    with open("tests/fixtures/dummy_binary", "rb") as f:
        elf_file = ELFFile(f)
        result = extract_strings(elf_file)
        assert isinstance(result, list)
        assert any("Hello" in s for s in result)  # because our hello.c binary prints "Hello"
