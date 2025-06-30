# SecElf

**A multi-stage ELF binary analysis and vulnerability mapping tool.**

---

## What is SecElf?

SecElf is a security analysis pipeline for ELF binaries. It:
- extracts strings, symbols, and linked libraries (Stage A)
- maps libraries to packages using RPM (Stage B)
- cross-references packages with CVEs from the cvelist (Stage C)

---

## Installation

SecElf currently requires:
- Python 3.8+
- pip to install dependencies (coming soon in requirements.txt)
- Linux system with `rpm` available (for Stage B)
- pyelftools Python library

---

## Quick Start

```bash
# Stage A
python scripts/run_stagea.py /path/to/binary

# Stage B
python scripts/run_stageb.py

# Stage C
python scripts/run_stagec.py
