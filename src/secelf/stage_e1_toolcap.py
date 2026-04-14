# stage_e1_toolcap.py
# Stage E1: Runtime capability evidence collection.
#
# Goal:
#   For each commercial EDA tool binary, collect raw runtime evidence using strace,
#   then split the trace into smaller evidence files for later manual/table analysis.
#
# This stage does NOT make final table decisions.
# It only organizes evidence into categories such as:
#   - artifact access
#   - log access
#   - config access
#   - temp/other file access
#   - shell invocation
#   - external tool invocation

import os
import re
import subprocess


def safe_name(tool, version):
    """
    Convert tool name and version into a safe folder name.

    Example:
        tool='Genus', version='21.17'
        returns: Genus_21_17
    """
    return f"{tool.replace(' ', '')}_{version.replace('.', '_')}"


def write_filtered_file(raw_trace, output_file, pattern):
    """
    Read the raw strace file and write only lines matching a regex pattern.

    raw_trace:
        Full strace output file.

    output_file:
        Smaller categorized evidence file.

    pattern:
        Regex pattern used to identify relevant lines.
    """
    with open(raw_trace, "r", errors="ignore") as f:
        lines = f.readlines()

    matches = [
        line for line in lines
        if re.search(pattern, line, re.IGNORECASE)
    ]

    with open(output_file, "w") as out:
        out.writelines(matches)

def collect_help_output(binary_path, tool_dir):
    """
    Try common help flags and save output.

    Output:
        help.txt
    """
    help_file = os.path.join(tool_dir, "help.txt")

    help_flags = ["-help", "--help", "-h"]

    with open(help_file, "w") as out:
        for flag in help_flags:
            out.write(f"\n===== {flag} =====\n")
            try:
                result = subprocess.run(
                    [binary_path, flag],
                    timeout=10,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    errors="ignore",
                )
                out.write(result.stdout)
            except Exception as e:
                out.write(f"[ERROR] Help flag {flag} failed: {e}\n")
def collect_proc_status(binary_path, tool_dir):
    """
    Launch the binary briefly and capture /proc/<pid>/status.

    Why:
        /proc/<pid>/status contains privilege/capability fields such as:
            - Uid / Gid
            - CapInh
            - CapPrm
            - CapEff
            - CapBnd
            - NoNewPrivs

    Output:
        proc_status.txt

    Note:
        Some tools exit very quickly or require environment setup.
        In that case, the file records the error instead of failing the stage.
    """
    proc_file = os.path.join(tool_dir, "proc_status.txt")

    with open(proc_file, "w") as out:
        try:
            proc = subprocess.Popen(
                [binary_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            status_path = f"/proc/{proc.pid}/status"
            out.write(f"PID: {proc.pid}\n")
            out.write(f"Status file: {status_path}\n\n")

            try:
                with open(status_path, "r", errors="ignore") as f:
                    out.write(f.read())
            except Exception as e:
                out.write(f"[ERROR] Could not read proc status: {e}\n")

            proc.terminate()

            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()

        except Exception as e:
            out.write(f"[ERROR] Could not launch binary for proc status: {e}\n")
def run_strace(tool, version, binary_path, output_root="outputs/stageE1"):
    """
    Run strace on one EDA tool binary and save categorized evidence.

    Output structure:
        outputs/stageE1/<tool_version>/
            strace.txt
            artifact_access.txt
            log_access.txt
            config_access.txt
            other_access.txt
            shell_invocation.txt
            external_tools.txt
    """

    # Skip placeholder or invalid paths.
    if binary_path in ["TODO", "MISSING", "SKIPPED", "NOT_A_TOOL"] or not os.path.exists(binary_path):
        print(f"[SKIP] {tool} {version} → invalid or missing binary path")
        return None

    # Create per-tool output folder.
    name = safe_name(tool, version)
    tool_dir = os.path.join(output_root, name)
    os.makedirs(tool_dir, exist_ok=True)

    # Raw strace output.
    raw_trace = os.path.join(tool_dir, "strace.txt")

    # Trace file access and process execution.
    # openat  → file/library/config/temp access
    # execve  → tool launch, shell invocation, external helper programs
    cmd = [
        "strace",
        "-f",
        "-e",
        "trace=openat,execve",
        "-o",
        raw_trace,
        binary_path,
    ]

    print(f"[RUN] strace → {tool} {version}")

    try:
        # Timeout prevents interactive EDA tools from hanging forever.
        subprocess.run(
            cmd,
            timeout=20,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception as e:
        # Some tools may timeout or exit strangely.
        # We still keep whatever strace captured before termination.
        print(f"[WARN] strace ended for {tool} {version}: {e}")

    # Evidence categories used later to fill the capability table.
    filters = {
        # Design artifacts and technology files.
        "artifact_access.txt": r"\.v|\.sv|\.lef|\.def|\.gds|\.lib|\.sdc|\.spef",

        # Runtime logs and text logs.
        "log_access.txt": r"\.log|stdout|stderr|run\.log",

        # Configuration files and system configuration.
        "config_access.txt": r"\.cfg|\.conf|\.rc|\.ini|\.xml|/etc/",

        # Temporary files, scratch files, and miscellaneous outputs.
        "other_access.txt": r"/tmp|/var/tmp|\.dat|\.out|scratch",

        # Explicit shell invocation.
        "shell_invocation.txt": r'execve\("/bin/sh"|execve\("/usr/bin/sh"|execve\("/bin/bash"',

        # All executed programs.
        # This includes the main tool binary and any helper programs.
        "external_tools.txt": r"execve",
    }

    # Generate categorized evidence files.
    for filename, pattern in filters.items():
        write_filtered_file(
            raw_trace,
            os.path.join(tool_dir, filename),
            pattern,
        )
    collect_help_output(binary_path, tool_dir)
    collect_proc_status(binary_path, tool_dir)
    return tool_dir