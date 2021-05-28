#!/usr/bin/env python3

import json
import os
import re
import subprocess
import sys
import tree_sitter

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

TMP = '/tmp'
TMP_LANG_CPP = os.path.join(TMP, 'tree-sitter-cpp')
GIT_LANG_CPP = 'https://github.com/tree-sitter/tree-sitter-cpp'
TREE_SITTER_BIN = os.path.join(TMP, 'tree_sitter_langs.so')

CONFIG_FILE_SOURCE_PATCHES = 'config_source_fixes.json'


######################################
# tree-sitter utils
######################################

# Gets the tree-sitter parser up and running
def prepare_tree_sitter():
    # Download and compile tree-sitter languages
    if not os.path.isdir(TMP_LANG_CPP):
        subprocess.run(['git', 'clone', GIT_LANG_CPP], cwd=TMP, check=True)
    tree_sitter.Language.build_library(TREE_SITTER_BIN, [TMP_LANG_CPP])
    # Setup the parser
    # The C++ language definition should work for C, too
    cpp_language = tree_sitter.Language(TREE_SITTER_BIN, 'cpp')
    cpp_parser = tree_sitter.Parser()
    cpp_parser.set_language(cpp_language)
    return cpp_parser

# Returns the code snippet that is marked by tree-sitter start- and end-points
def get_code_between(source, start_point, end_point):
    source_lines = source.split('\n')
    # Start and end in same line
    if start_point[0] == end_point[0]:
        return source_lines[start_point[0]][start_point[1]:end_point[1]]
    # Start and end in different lines
    selection = source_lines[start_point[0]][start_point[1]:]
    for line in range(start_point[0] + 1, end_point[0]):
        selection += '\n' + source_lines[line]
    selection += '\n' + source_lines[end_point[0]][:end_point[1]]
    return selection

# Traverses a node tree and returns nodes of a certain type
def find_nodes_by_type(node, type_name):
    if node.type == type_name:
        return [node]
    results = []
    for child in node.children:
        results += find_nodes_by_type(child, type_name)
    return results


######################################
# general stuff
######################################

# Reads the specified source file and applies patches from the config file
static_source_patches = None
def read_source_with_fixes(filename):
    global static_source_patches
    # Load patches from the config file
    if static_source_patches is None:
        with open(CONFIG_FILE_SOURCE_PATCHES, 'r') as f:
            static_source_patches = json.loads(f.read())
    # Read source file and apply rules
    eprint(f'Reading: {filename}')
    with open(filename, 'r') as f:
        source = f.read()
    for fix_s, fix_r in static_source_patches.items():
        source = re.sub(fix_s, fix_r, source, flags=re.MULTILINE)
    return source.replace('\r\n', '\n')


######################################
# implementation of functionality
######################################

# Parse a source snippet with tree-sitter
def parse_snippet(cpp_parser, source_code):
    return cpp_parser.parse(source_code.encode()).root_node.sexp()


# Searches the source file for a function containing the line number and returns it's declaration
def get_function_decl(cpp_parser, source_file, line_number):
    # Get source file
    source = read_source_with_fixes(source_file)

    # Validate line number
    total_lines = source.count('\n') + 1
    if line_number < 1 or line_number > total_lines:
        eprint(f'Line number {line_number} not in range 1 to {total_lines}')
        sys.exit(1)

    # Parse source file end extract function blocks
    lineidx = line_number - 1
    tree = cpp_parser.parse(source.encode())
    func_nodes = find_nodes_by_type(tree.root_node, 'function_definition')
    for func_node in func_nodes:
        if lineidx >= func_node.start_point[0] and lineidx <= func_node.end_point[0]:
            # Return code between first and last but one node in this function definition.
            # The last node is for the compound statement.
            return get_code_between(source, func_node.children[0].start_point, func_node.children[-2].end_point)
    # No function containing this line found
    return None

# Searches a list of header files for function declarations and returns them as a list
def find_function_decls(parser, header_files):
    function_decls = []
    for header_file in header_files:
        source = read_source_with_fixes(header_file)
        tree = parser.parse(source.encode())
        decl_nodes = find_nodes_by_type(tree.root_node, 'declaration')
        for decl_node in decl_nodes:
            #print('Types: ' + ' '.join([c.type for c in decl_node.children]))
            if any(child.type == 'function_declarator' for child in decl_node.children):
                function_decls.append(get_code_between(source, decl_node.start_point, decl_node.end_point).replace('\n', ' '))
    return function_decls

# Searches the list of source files for all function definitions and returns them as a list
def find_function_defs(parser, source_files):
    function_defs = []
    for source_file in source_files:
        # Get source
        source = read_source_with_fixes(source_file)
        # Search function definitions
        tree = parser.parse(source.encode())
        func_nodes = find_nodes_by_type(tree.root_node, 'function_definition')
        for func_node in func_nodes:
            # Function declaration is first to last but one child node, last one is the compound statement
            func_def = get_code_between(source, func_node.children[0].start_point, func_node.children[-2].end_point)
            # Remove newlines and whitespace before/after
            func_def = ''.join([line.strip() for line in func_def.split('\n')])
            function_defs.append(func_def)
    return function_defs

# Searches the list of source files for all function calls and returns function names as a list
def find_function_calls(parser, source_files):
    function_names = []
    for source_file in source_files:
        # Get source
        source = read_source_with_fixes(source_file)
        # Search function calls
        tree = parser.parse(source.encode())
        func_call_nodes = find_nodes_by_type(tree.root_node, 'call_expression')
        for func_call_node in func_call_nodes:
            # There are different types for function identifiers, look for them in the call_expression
            for child in func_call_node.children:
                if child.type in ['identifier', 'scoped_identifier', 'field_expression']:
                    # For field expressions only keep the actual function name
                    func_name = get_code_between(source, child.start_point, child.end_point)
                    for func_sep in ['.', '->']:
                        last_sep_idx = func_name.rfind(func_sep)
                        if last_sep_idx != -1:
                            func_name = func_name[last_sep_idx + len(func_sep):]
                    function_names.append(func_name)
    return sorted(set(function_names))




def print_usage_and_exit():
    eprint(f'Usage: {sys.argv[0]} parse')
    eprint(f'Usage: {sys.argv[0]} function_decl <file path> <line number>')
    eprint(f'Usage: {sys.argv[0]} function_snippet <file path> <line number>')
    eprint(f'Usage: {sys.argv[0]} find_func_decls <file path>...')
    eprint(f'Usage: {sys.argv[0]} find_func_defs <file path>...')
    eprint(f'Usage: {sys.argv[0]} find_func_calls <file path>...')
    sys.exit(1)

def main():
    # Check usage, get arguments and perform sanity checks
    if len(sys.argv) < 2:
        print_usage_and_exit()
    arg_cmd = sys.argv[1]
    if arg_cmd in ['function_decl', 'function_snippet']:
        if len(sys.argv) < 4:
            print_usage_and_exit()
        arg_source_file = sys.argv[2]
        if not os.path.isfile(arg_source_file):
            eprint(f'{arg_source_file} not found')
            sys.exit(1)
        try:
            arg_line_number = int(sys.argv[3])
        except ValueError:
            eprint(f'{sys.argv[3]} is not a number')
            sys.exit(1)
    elif arg_cmd in ['find_func_decls', 'find_func_defs', 'find_func_calls']:
        if len(sys.argv) < 3:
            print_usage_and_exit()
        arg_source_files = sys.argv[2:]
        for source_file in arg_source_files:
            if not os.path.isfile(source_file):
                eprint(f'{source_file} not found')
                sys.exit(1)
    elif arg_cmd == 'parse':
        # No parameters to check, we're reading input from stdin
        source_snippet = sys.stdin.read()
    else:
        eprint(f'Unknown command!')
        sys.exit(1)
        

    # Download and compile tree-sitter languages
    cpp_parser = prepare_tree_sitter()

    # Call command implementation functions
    if arg_cmd == 'parse':
        parsed_ast = parse_snippet(cpp_parser, source_snippet)
        print(parsed_ast)
        sys.exit(0)

    if arg_cmd == 'function_decl':
        func_decl = get_function_decl(cpp_parser, arg_source_file, arg_line_number)
        if func_decl is None:
            eprint('Could not find function!')
            sys.exit(1)
        print(func_decl)
        sys.exit(0)

    if arg_cmd == 'find_func_decls':
        func_decls = find_function_decls(cpp_parser, arg_source_files)
        for func_decl in func_decls:
            print(func_decl)
        sys.exit(0)

    if arg_cmd == 'find_func_defs':
        func_defs = find_function_defs(cpp_parser, arg_source_files)
        for func_def in func_defs:
            print(func_def)
        sys.exit(0)

    if arg_cmd == 'find_func_calls':
        func_calls = find_function_calls(cpp_parser, arg_source_files)
        for func_call in func_calls:
            print(func_call)
        sys.exit(0)


    eprint('Whoopsie, this isn\'t implemented yet!')
    sys.exit(1)

if __name__ == '__main__':
    main()
