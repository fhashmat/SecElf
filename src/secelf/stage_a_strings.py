# ---------------------------------------------------------------
# stage_a_strings.py
#
# Context:
#   Stage A (Strings) focuses purely on extracting printable
#   ASCII strings from the .rodata section of an ELF binary.
#
# Flow:
#   1. Parse ELF with pyelftools
#   2. Locate .rodata
#   3. Extract printable strings
#   4. Save results to stagea_strings.csv
#
# How To Run:
#   PYTHONPATH=src python3 scripts/run_stagea_strings.py <binary>
#   PYTHONPATH=src python3 scripts/run_stagea_strings.py tests/fixtures/dummy_binary 
#
# ---------------------------------------------------------------
from elftools.elf.elffile import ELFFile
import csv
import re
import os

# ---------------------------------------------------------------
# stage_a_strings_process()
#
# Description:
#   Extracts printable ASCII strings from an ELF binary and
#   saves them to a separate CSV for later analysis.
#
# Inputs:
#   binary_path (str): path to the ELF binary
#
# Returns:
#   None (writes stagea_strings.csv to disk)
# ---------------------------------------------------------------


def extract_strings(elf_file):
    """
    Extract printable strings from all ELF sections and track their section of origin.
    Returns list of (section_name, string) tuples.
    """
    string_entries = []
    for section in elf_file.iter_sections():
        if not section.is_null() and hasattr(section, 'data'):
            try:
                raw_data = section.data()
                found = re.findall(rb"[ -~]{2,}", raw_data)
                decoded = [s.decode('utf-8', errors='ignore') for s in found]
                for s in decoded:
                    string_entries.append((section.name, s))
            except Exception:
                continue
    return string_entries






def stage_a_strings_process(binary_path):
    """
    Extract strings from .rodata and write to a separate CSV.
    """
    with open(binary_path, "rb") as fp:
        elf_file = ELFFile(fp)
        strings = extract_strings(elf_file)

    binary_name = os.path.basename(binary_path)
    csv_name = f"strings_extracted_{binary_name}.csv"
     # ---- NEW: write under stageAstrings/<tool_name>/ ----
    tool_name = os.path.splitext(binary_name)[0]     # e.g., "genus" from "genus"
    out_dir = os.path.join("stageAstrings", tool_name)
    os.makedirs(out_dir, exist_ok=True)
    csv_name = os.path.join(out_dir, csv_name)       # stageAstrings/<tool>/strings_extracted_<binary>.csv
    # ----------------------------------------------------

    with open(csv_name, "w", newline="") as out:
        writer = csv.writer(out)
        writer.writerow(["Section", "String"])
        for section, string in strings:
            writer.writerow([section, string])


    print(f"Extracted strings written to {csv_name}")



