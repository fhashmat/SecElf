# stage_e1_toolcap.py
# This stage analyzes commercial tool binaries for system interactions
# such as file access, external tool usage, and security-related features.

# Functions will be added step-by-step.
import os
import subprocess

def run_strace(tool, version, binary_path, output_root="outputs/stagee1"):
    """
    Runs strace on the given binary and saves output to:
      outputs/stagee1/<tool>_<version>_strace.txt
    """
    # Skip if binary_path is missing or not executable
    if binary_path in ["TODO", "MISSING", "SKIPPED", "NOT_A_TOOL"] or not os.path.exists(binary_path):
        print(f"[SKIP] {tool} {version} → invalid or missing binary path")
        return None

    # Output file path
    os.makedirs(output_root, exist_ok=True)
    filename = f"{tool.replace(' ', '')}_{version.replace('.', '_')}_strace.txt"
    output_path = os.path.join(output_root, filename)

    # Run strace
    cmd = ["strace", "-f", "-e", "trace=openat,execve", "-o", output_path, binary_path]
    print(f"[RUN] strace → {tool} {version}")
    try:
        subprocess.run(cmd, timeout=20, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        print(f"[ERROR] strace failed for {tool} {version}: {e}")
        return None

    return output_path
