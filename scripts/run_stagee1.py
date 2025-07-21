#!/usr/bin/env python3

# run_stagee1.py
# CLI to run Stage E1: tool capability analysis

# -------------------------------
# Hardcoded list of commercial tool binaries
# Each entry includes: tool name, version, path (or placeholder), and status
# -------------------------------
binaries_to_check = [
    {
        "tool": "Genus",
        "version": "21.17",
        "path": "/package/eda/cadence/GENUS2117/tools.lnx86/genus/bin/64bit/genus",
        "status": "not stripped"
    },
    {
        "tool": "Allegro",
        "version": "17.4",
        "path": "/package/eda/cadence/IC618/tools/bin/allegro_batch.exe",
        "status": "not stripped"
    },
    {
        "tool": "Allegro",
        "version": "23.1",
        "path": "/package/eda/cadence/SPB231/tools.lnx86/bin/allegro_batch.exe",
        "status": "not stripped"
    },
    {
        "tool": "Assura",
        "version": "6.17.4.16",
        "path": "MISSING",  # Not accessible
        "status": "not found"
    },
    {
        "tool": "EMX",
        "version": "6.3",
        "path": "/package/eda/cadence/INTEGRAND63/tools.lnx86/emx/bin/64bit/emx",
        "status": "stripped"
    },
    {
        "tool": "Jasper",
        "version": "2024.12",
        "path": "/package/eda/cadence/jasper_2024.12p002/Linux64/bin/jg_console",
        "status": "stripped"
    },
    {
        "tool": "Virtuoso",
        "version": "6.1.8",
        "path": "TODO",  # Placeholder
        "status": "pending"
    },
    {
        "tool": "GPdk45",
        "version": "6.0",
        "path": "NOT_A_TOOL",  # Docs only
        "status": "not applicable"
    },
        {
        "tool": "Assura",
        "version": "6.18.4.16",
        "path": "MISSING",  # Broken path
        "status": "not found"
    },
    {
        "tool": "Assura",
        "version": "23.1.4.17",
        "path": "MISSING",  # Broken path
        "status": "not found"
    },
    {
        "tool": "Conformal",
        "version": "18.10",
        "path": "SKIPPED",  # Symbolic link complexity
        "status": "skipped"
    },
    {
        "tool": "Conformal",
        "version": "21.20",
        "path": "SKIPPED",  # Symbolic link complexity
        "status": "skipped"
    },
    {
        "tool": "Conformal",
        "version": "23.10",
        "path": "SKIPPED",  # Symbolic link complexity
        "status": "skipped"
    },
    {
        "tool": "Conformal",
        "version": "24.10",
        "path": "SKIPPED",  # Symbolic link complexity
        "status": "skipped"
    },
    {
        "tool": "DDI",
        "version": "22.14",
        "path": "SEE_GENUS_PATHS",  # Might be embedded in genus
        "status": "combined tool"
    },
    {
        "tool": "DDI",
        "version": "23.11",
        "path": "SEE_GENUS_PATHS",  # Might be embedded in genus
        "status": "combined tool"
    },
    {
        "tool": "DDI",
        "version": "23.14",
        "path": "SEE_GENUS_PATHS",  # Might be embedded in genus
        "status": "combined tool"
    },
    {
        "tool": "EMX",
        "version": "6.0",
        "path": "/package/eda/cadence/INTEGRAND60/bin/emx",
        "status": "stripped"
    },
    {
        "tool": "EMX",
        "version": "6.2",
        "path": "/package/eda/cadence/INTEGRAND62/tools.lnx86/emx/bin/64bit/emx",
        "status": "stripped"
    },
    {
        "tool": "EMX",
        "version": "23.2",
        "path": "/package/eda2/cadence/EMX20232/tools.lnx86/emx/bin/64bit/emx",
        "status": "stripped"
    },
    {
        "tool": "GPdk45",
        "version": "6.0",
        "path": "NOT_A_TOOL",
        "status": "documentation only"
    },
    {
        "tool": "Incisive",
        "version": "15.2",
        "path": "/package/eda/cadence/INCISIVE152.05",
        "status": "not found"
    },
    {
        "tool": "Innovus",
        "version": "21.12",
        "path": "/package/eda/cadence/INNOVUS211/tools.lnx86/innovus/bin/64bit/innovus",
        "status": "not stripped"
    },
        {
        "tool": "Innovus",
        "version": "21.17",
        "path": "/package/eda/cadence/INNOVUS211.7/tools.lnx86/innovus/bin/64bit/innovus",
        "status": "not stripped"
    },
    {
        "tool": "Liberate",
        "version": "23.10",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "Liberate",
        "version": "23.16",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "MMSIM",
        "version": "151",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "Modus",
        "version": "21.10",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "Modus",
        "version": "22.11",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "Modus",
        "version": "23.11",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "MVS",
        "version": "20.11",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "MVS",
        "version": "21.12",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "Pegasus",
        "version": "21.30",
        "path": "TODO",
        "status": "pending"
    },
        {
        "tool": "Pegasus",
        "version": "22.23",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "Pegasus",
        "version": "22.24",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "Pegasus",
        "version": "23.20",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "Pegasus",
        "version": "24.10",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "PVS",
        "version": "21.12",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "PVS",
        "version": "22.21",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "PVS",
        "version": "23.11",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "Quantus",
        "version": "20.12",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "Quantus",
        "version": "21.22",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "Quantus",
        "version": "22.10",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "Quantus",
        "version": "22.11",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "Quantus",
        "version": "23.11",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "Sigrity",
        "version": "2019",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "Sigrity",
        "version": "2023.1",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "Sigrity",
        "version": "2024.0",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "SPB",
        "version": "23.10",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "Spectre",
        "version": "1.5.1",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "Spectre",
        "version": "1.7.1",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "Spectre",
        "version": "1.9.1",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "Spectre",
        "version": "20.10",
        "path": "TODO",
        "status": "pending"
    },
        {
        "tool": "Spectre",
        "version": "21.10",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "Spectre",
        "version": "21.10.612",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "Spectre",
        "version": "21.10.824",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "Spectre",
        "version": "23.10.063",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "Spectre",
        "version": "23.10.509",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "Spectre",
        "version": "24.10",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "SSV",
        "version": "21.12",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "SSV",
        "version": "22.12",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "SSV",
        "version": "23.00",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "SSV",
        "version": "23.11",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "UltraSim",
        "version": "18.1",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "Virtuoso Advanced",
        "version": "20.1.14",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "Virtuoso Advanced",
        "version": "20.1.33",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "Virtuoso Advanced",
        "version": "20.1.34",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "Virtuoso",
        "version": "6.1.7",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "Virtuoso",
        "version": "23.10",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "Virtuoso",
        "version": "23.10.07",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "Virtuoso",
        "version": "23.10.11",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "Virtuoso",
        "version": "23.10.060",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "VManager",
        "version": "21.09",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "VManager",
        "version": "23.03",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "VManager",
        "version": "24.03",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "Xcelium",
        "version": "21.09",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "Xcelium",
        "version": "22.09",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "Xcelium",
        "version": "23.03",
        "path": "TODO",
        "status": "pending"
    },
    {
        "tool": "Xcelium",
        "version": "24.03",
        "path": "TODO",
        "status": "pending"
    },


]


def main():
    print("[INFO] Stage E1 runner started")

    # Hardcoded list of commercial tool binaries
    binaries = [
        "/package/eda2/cadence/DDI2314/INNOVUS231/tools.lnx86/genus/bin/64bit/genus",
        # Add more paths below as needed
    ]

    for entry in binaries_to_check:
        print(f"[INFO] Tool: {entry['tool']} {entry['version']} -> {entry['path']} [{entry['status']}]")



if __name__ == "__main__":
    main()
