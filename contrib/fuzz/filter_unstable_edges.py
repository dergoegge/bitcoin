#!/usr/bin/env python3
import argparse
import subprocess

def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description='''Print unstable edges''',
    )
    parser.add_argument(
        "--afl-edge-id-file",
        help="Path to afl++'s file containing all edge ids and symbols of the binary",
        type=str,
        required=True)
    parser.add_argument(
        "--afl-fuzzer-stats",
        help="Path to afl++'s fuzzer_stats file",
        type=str,
        required=True)
    parser.add_argument(
        "--output-file",
        help="Path to the output file where unstable symbols will be written",
        type=str,
        required=True)
    parser.add_argument(
        "--only-print-unstable",
        help="Whether to print just the unstable symbols from the edge id file",
        type=bool)

    args = parser.parse_args()

    unstable_edges = []

    with open(args.afl_fuzzer_stats, "r") as fuzzer_stats_file:
        for line in fuzzer_stats_file:
            if line.startswith("var_bytes"):
                unstable_edges = line.split(":")[1].strip().split(" ")
                break

    seen_syms = set()
    with open(args.afl_edge_id_file, "r") as edge_id_file, open(args.output_file, "w") as output_file:
        for line in edge_id_file:
            for edge in unstable_edges:
                if f"edgeID={edge}" in line:
                    if args.only_print_unstable:
                        symbol = line.strip().split(" ")[1].split("=")[1]
                        if symbol not in seen_syms:
                            print(symbol)
                            output_file.write(symbol + "\n")

                        seen_syms.add(symbol)
                        
                    else:
                        print(line.strip())
                        output_file.write(line.strip() + "\n")

                    unstable_edges.remove(edge)
                    break


if __name__ == '__main__':
    main()
