#!/usr/bin/python3
import sys
import re
import argparse
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
        yield self.build_tree(self.hierarchy)

    def build_tree(self, hierarchy, parent=None):
        if parent is None:
            tree = Tree("Hierarchy")
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
            if value["flag"]:
                node = parent.add(f"[green]{text}[/green]")
            else:
                node = parent.add(text)
            self.add_nodes(value.get('children', {}), node)
            if should_expand:
                nodes_to_expand.append(node)
        for node in nodes_to_expand:
            node.expand()

    def has_flag_true(self, node):
        """Check if the node or any of its children have flag=True."""
        if node.get('flag', False):
            return True
        if 'children' in node:
            for child in node['children'].values():
                if self.has_flag_true(child):
                    return True
        return False


def demangle(symbol):
    try:
        if symbol.endswith("@plt"):
            symbol = symbol[:-4]
        result = subprocess.run(['c++filt', symbol], capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return symbol


def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description='''Creates a function hierarchy and highlights unstable functions''',
    )
    parser.add_argument(
        "--binary-file",
        help="Path to binary file from which to generate the call graph",
        type=str,
        required=True)
    parser.add_argument(
        "--unstable-functions-file",
        help="Path to file that contains the unstable functions",
        type=str,
        required=True)
    parser.add_argument(
        "--target-function",
        help="The target function that is the top of the call graph (e.g. fuzz_target_name_fuzz_target)",
        type=str,
        required=True)
    parser.add_argument(
        "--skip-strings-file",
        help="Path to file that contains strings that if at the start of a function name, that function is skipped",
        type=str,
        default=None
    )

    args = parser.parse_args()
    binary_file = args.binary_file
    unstable_functions_file = args.unstable_functions_file
    skip_strings_file = args.skip_strings_file
    target_function = args.target_function
    
    with open(unstable_functions_file, 'r') as unstable_file:
        unstable_functions = set(line.strip() for line in unstable_file if line.strip())

    strings_to_skip = set()
    if skip_strings_file:
        with open(skip_strings_file, 'r') as skip_file:
            strings_to_skip = set(line.strip() for line in skip_file if line.strip())

    try:
        lines = check_output(["objdump", "-d", args.binary_file]).splitlines()
    except:
        exit()

    G = nx.DiGraph()
    curFunc = None

    for l in lines:
        l = l.decode('utf-8')
        m = re.match(r'^([0-9a-zA-Z]+)\s+<(.*)>:$', l)
        if m:
            curFunc = m.group(2)
            continue

        if curFunc == None:
            continue

        m = re.match(r'^.*\bcall\s+([0-9a-zA-Z])+\s+<(.*)>$', l)
        if m:
            G.add_edge(curFunc, m.group(2))
    
    seen_edges = set()

    def create_hierarchy(G, root):
        demangled = demangle(root)
        node = {
            demangled: {
                "children": {},
                "flag": root in unstable_functions,
            }
        }
        for child in G.successors(root):
            edge = (root, child)
            if edge in seen_edges:
                continue
            seen_edges.add(edge)
            
            demangled_child = demangle(child)
            if child in unstable_functions and any(demangled_child.startswith(string) for string in strings_to_skip):
                continue            
            
            node[demangled]["children"] = node[demangled]["children"] | create_hierarchy(G, child)
        return node
    
    
    target_nodes = [node for node in G.nodes() if target_function in node]
    hierarchy = {}
    
    # Do we really need the for loop here or should we just do hierarchy = hierarchy | create_hierarchy(G, target_node)
    for root in target_nodes:
        hierarchy = hierarchy | create_hierarchy(G, root)

    app = HierarchyViewer(hierarchy)
    app.run()

if __name__ == '__main__':
    main()
