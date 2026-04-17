#!/usr/bin/env python3

# run_stageb1.py
# CLI runner for Stage B1: Dependency Risk Metadata Enrichment

from secelf.stage_b1 import stage_b1_process

targets = [
    ("Genus", "21.17", "outputs/stageB/genus_21_17/packages_genus.csv"),
    ("Innovus", "21.12", "outputs/stageB/innovus_21_12/packages_innovus.csv"),
    ("Innovus", "21.17", "outputs/stageB/innovus_21_17/packages_innovus.csv"),
    ("Jasper", "2024.12", "outputs/stageB/jasper_2024_12/packages_jg_console.csv"),
    ("Assura", "6.18.4.16", "outputs/stageB/assura_6_18_4_16/packages_assura.csv"),
    ("Assura", "23.1.4.17", "outputs/stageB/assura_23_1_4_17/packages_assura.csv"),
]

def main():
    for tool, version, csv_path in targets:
        print(f"[RUN] Stage B1 → {tool} {version}")
        stage_b1_process(tool, version, csv_path)

if __name__ == "__main__":
    main()