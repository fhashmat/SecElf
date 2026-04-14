#!/usr/bin/env python3

from secelf.stage_e1_toolcap import run_strace

binaries_to_check = [
    {
        "tool": "Genus",
        "version": "21.17",
        "path": "/package/eda2/cadence/DDI2314/GENUS231/tools.lnx86/synth/bin/64bit/genus",
        "status": "not stripped",
    },
    {
        "tool": "Innovus",
        "version": "21.12",
        "path": "/package/eda/cadence/INNOVUS211/tools.lnx86/innovus/bin/64bit/innovus",
        "status": "not stripped",
    },
    {
        "tool": "Innovus",
        "version": "21.17",
        "path": "/package/eda/cadence/INNOVUS211.7/tools.lnx86/innovus/bin/64bit/innovus",
        "status": "not stripped",
    },
    {
        "tool": "Jasper",
        "version": "2024.12",
        "path": "/package/eda/cadence/jasper_2024.12p002/Linux64/bin/jg_console",
        "status": "stripped",
    },
    {
        "tool": "Assura",
        "version": "6.18.4.16",
        "path": "/package/eda/cadence/ASSURA416-618/tools.lnx86/assura/bin/64bit/assura",
        "status": "not stripped",
    },
    {
        "tool": "Assura",
        "version": "23.1.4.17",
        "path": "/package/eda2/cadence/ASSURA41/tools.lnx86/assura/bin/64bit/assura",
        "status": "not stripped",
    },
]

def main():
    print("[INFO] Stage E1 raw strace collection started")

    for entry in binaries_to_check:
        print(f"[INFO] Tool: {entry['tool']} {entry['version']}")
        output_file = run_strace(
            entry["tool"],
            entry["version"],
            entry["path"],
            output_root="outputs/stageE1"
        )

        if output_file:
            print(f"[OK] Saved strace to: {output_file}")

if __name__ == "__main__":
    main()
