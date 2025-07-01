import pytest
from secelf import stage_a

def test_stage_a_process_runs_without_crashing():
    """
    Dummy test to check stage_a_process executes on a test ELF.
    You will replace 'tests/fixtures/dummy_binary' with your actual test ELF later.
    """
    test_binary = "tests/fixtures/dummy_binary"  # placeholder path
    try:
        stage_a.stage_a_process(test_binary)
    except FileNotFoundError:
        pytest.skip("dummy ELF binary not present yet")
    except Exception as e:
        pytest.fail(f"stage_a_process raised an unexpected exception: {e}")
