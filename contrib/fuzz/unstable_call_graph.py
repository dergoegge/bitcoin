#!/usr/bin/python3
import sys
import re
import argparse
import json
import networkx as nx
import subprocess
from subprocess import check_output
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Tree


class HierarchyViewer(App):
    def __init__(self, hierarchy):
        super().__init__()
        self.hierarchy = hierarchy

    def compose(self) -> ComposeResult:
        yield Header()
        yield Footer()
        tree = self.build_tree(self.hierarchy)
        tree.root.expand()
        yield tree

    def build_tree(self, hierarchy, parent=None):
        if parent is None:
            tree = Tree('Hierarchy')
            root = tree.root
            self.add_nodes(hierarchy, root)
            return tree
        else:
            self.add_nodes(hierarchy, parent)

    def add_nodes(self, hierarchy, parent):
        nodes_to_expand = []
        for key, value in hierarchy.items():
            should_expand = self.has_flag_true(value)
            text = key[:100]
            if value['is_unstable']:
                node = parent.add(f'[green]{text}[/green]')
            else:
                node = parent.add(text)
            self.add_nodes(value.get('children', {}), node)
            if should_expand:
                nodes_to_expand.append(node)
        for node in nodes_to_expand:
            node.expand()

    def has_flag_true(self, node):
        # Check if the node or any of its children have flag=True
        if node.get('is_unstable', False):
            return True
        if 'children' in node:
            for child in node['children'].values():
                if self.has_flag_true(child):
                    return True
        return False


def demangle(symbol):
    try:
        if symbol.endswith('@plt'):
            symbol = symbol[:-4]
        result = subprocess.run(['c++filt', symbol], capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return symbol


def get_architecture(file_path):
    try:
        result = subprocess.run(['file', file_path], capture_output=True, text=True)
        output = result.stdout.strip()

        if 'x86-64' in output:
            return 'x86_64'
        elif 'aarch64' in output or 'arm64' in output:
            return 'arm64'
        else:
            return 'Unknown'

    except FileNotFoundError:
        print("The 'file' command is not available. Ensure it's installed.")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description='''Creates a function hierarchy and highlights unstable functions''',
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
        "--binary-file",
        help="Path to binary file from which to generate the call graph",
        type=str,
        required=True)
    parser.add_argument(
        "--target-function",
        help="The target function that is the top of the call graph (e.g. fuzz_target_name_fuzz_target)",
        type=str,
        required=True)
    parser.add_argument(
        "--ignored-prefixes",
        help="Path to file that contains strings that if at the start of a function name, that function is skipped",
        type=str,
        default=None)
    parser.add_argument(
        "--dump-hierarchy",
        help="Path to json file where the hierarchy will be dumped",
        type=str,
        default=None)
    parser.add_argument(
        "--dump-unstable",
        help="Path to file where unstable symbols will be dumped",
        type=str,
        default=None)
    parser.add_argument(
        "--no-tui",
        help="Whether to output the hierarchy to the terminal",
        action="store_true")

    args = parser.parse_args()

    unstable_edges = []
    unstable_functions = set()
    prefixes_to_ignore = set()

    with open(args.afl_fuzzer_stats, 'r') as fuzzer_stats_file:
        for line in fuzzer_stats_file:
            if line.startswith('var_bytes'):
                unstable_edges = line.split(":")[1].strip().split(" ")
                break

    with open(args.afl_edge_id_file, 'r') as edge_id_file:
        for line in edge_id_file:
            for edge in unstable_edges:
                if f'edgeID={edge}' in line:
                    function = line.strip().split(" ")[1].split("=")[1]
                    if function not in unstable_functions:
                        unstable_functions.add(function)

    if args.dump_unstable:
        with open(args.dump_unstable, 'w') as unstable_file:
            for function in unstable_functions:
                unstable_file.write(function + '\n')

    if args.ignored_prefixes:
        with open(args.ignored_prefixes, 'r') as ignore_file:
            prefixes_to_ignore = set(line.strip() for line in ignore_file if line.strip())

    try:
        lines = check_output(["objdump", "-d", args.binary_file]).splitlines()
    except:
        exit()

    G = nx.DiGraph()
    curFunc = None
    architecture = get_architecture(args.binary_file)

    if architecture == 'x86_64':
        call_pattern = r'^.*\bcall\s+([0-9a-zA-Z])+\s+<(.*)>$'
    elif architecture == 'arm64':
        call_pattern = r'^.*\bbl\s+([0-9a-zA-Z])+\s+<(.*)>$'
    else:
        raise ValueError("Unsupported architecture: " + architecture)

    for l in lines:
        l = l.decode('utf-8')
        m = re.match(r'^([0-9a-zA-Z]+)\s+<(.*)>:$', l)
        if m:
            curFunc = m.group(2)
            continue
        if curFunc == None:
            continue
        m = re.match(call_pattern, l)
        if m:
            G.add_edge(curFunc, m.group(2))

    seen_edges = set()

    def create_hierarchy(G, root):
        demangled = demangle(root)
        node = {
            demangled: {
                'children': {},
                'is_unstable': root in unstable_functions and not any(demangled.startswith(prefix) for prefix in prefixes_to_ignore)
            }
        }
        for child in G.successors(root):
            edge = (root, child)
            if edge in seen_edges:
                continue
            seen_edges.add(edge)
            node[demangled]['children'] = node[demangled]['children'] | create_hierarchy(G, child)
        return node

    target_node = next((node for node in G.nodes() if args.target_function in node), None)
    if target_node is None:
        print(f"Error: No symbol matching '{target_function}' was found.")
        exit(1)

    hierarchy = {}
    hierarchy = hierarchy | create_hierarchy(G, target_node)

    if args.dump_hierarchy:
        with open(args.dump_hierarchy, 'w') as hierarchy_file:
            json.dump(hierarchy, hierarchy_file)

    if not args.no_tui:
        app = HierarchyViewer(hierarchy)
        app.run()

if __name__ == '__main__':
    main()
