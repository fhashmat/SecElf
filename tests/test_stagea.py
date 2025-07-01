import pytest
from secelf import stage_a
from secelf.stage_a import extract_strings
from elftools.elf.elffile import ELFFile

def test_stage_a_process_runs_without_crashing():
    """
    Dummy test to check stage_a_process executes on a test ELF.
    You will replace 'tests/fixtures/dummy_binary' with your actual test ELF later.
    """
    test_binary = "tests/fixtures/dummy_binary"
    try:
        stage_a.stage_a_process(test_binary)
    except FileNotFoundError:
        pytest.skip("dummy ELF binary not present yet")
    except Exception as e:
        pytest.fail(f"stage_a_process raised an unexpected exception: {e}")

def test_extract_strings_returns_nonempty_list():
    """
    Tests that extract_strings returns a non-empty list from the dummy binary.
    """
    with open("tests/fixtures/dummy_binary", "rb") as f:
        elf_file = ELFFile(f)
        result = extract_strings(elf_file)
        assert isinstance(result, list)
        assert any("Hello" in s for s in result)  # because our hello.c binary prints "Hello"
