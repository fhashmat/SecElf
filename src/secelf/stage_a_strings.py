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
#
# ---------------------------------------------------------------
from elftools.elf.elffile import ELFFile
import csv
import re
from secelf.stage_a_libraries import extract_strings
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
def stage_a_strings_process(binary_path):
    """
    Extract strings from .rodata and write to a separate CSV.
    """
    with open(binary_path, "rb") as fp:
        elf_file = ELFFile(fp)
        strings = extract_strings(elf_file)

    with open("stagea_strings.csv", "w", newline="") as out:
        writer = csv.writer(out)
        writer.writerow(["String"])
        for s in strings:
            writer.writerow([s])

    print("Extracted strings written to stagea_strings.csv")
