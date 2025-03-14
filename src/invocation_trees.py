import snapshot_utils
import json
import csv
from datetime import datetime
import dateutil.parser
import copy
import sys

class Node:
    def __init__(self, parent, n_type, name, vuln_date, full_path, date):
        self.children = []
        self.parent = parent
        self.n_type = n_type
        self.name = name
        if n_type != "Function" and ("util" in name.lower() or "helper" in name.lower() or (parent is not None and parent.util)):
            self.util = True
        else:
            self.util = False
        if n_type != "Function" and ("test" in name.lower() or (parent is not None and parent.test)):
            self.test = True
        else:
            self.test = False
        self.full_path = full_path
        self.vuln_date = vuln_date
        self.callers = []
        self.calls = []
        self.start_line = None
        self.end_line = None
        if vuln_date is not None and vuln_date < date:
            self.vuln = True
        else:
            self.vuln = False
    
    def add_child(self, node):
        self.children.append(node)
    
    def set_start(self, line):
        self.start_line = line
    
    def set_end(self, line):
        self.end_line = line
    
    def add_caller(self, caller):
        # print(self.callers)
        self.callers.append(caller)

    def add_call(self, target):
        # print(self.calls)
        self.calls.append(target)



def build_current_blame(prior, new_file):
    # Given the prior snapshot's blame, and new blame file path
    # Build a collective set of blame data
    with open(new_file, 'r') as file:
        for line in file:
            obj = json.loads(line)
            prior.update(obj)
    return prior
            

def build_current_calls(prior, new_file, repo_dir):
    # Given the prior snapshot's calls, and new calls file path
    # Build a collective set of call data. Remove Non-relative Elements of Path
    prior_calls = {}
    # Place Calls into a Dictionary of file -> current tupple 
    for call in prior:
        path = call[0]
        if path not in prior_calls:
            prior_calls[path] = [call]
        else:
            prior_calls[path].append(call)

    calls = {}
    with open(new_file) as file:
        for line in file:
            lines = line.strip().split(",")
            if len(lines) == 3:
                path = lines[0]
                line_no = int(lines[1])
                target = lines[2]
                if repo_dir in path:
                    path = path[len(repo_dir)+1:]
                if path not in calls:
                    calls[path] = [(path, line_no, target)]
                else:
                    calls[path].append((path, line_no, target))
    
    prior_calls.update(calls)
    # Expand out calls again
    out_list = []
    for call in prior_calls:
        for entry in prior_calls[call]:
            out_list.append(entry)
    # print(prior_calls)
    return out_list


def ident_ctag_functions(ctag_file):
    # Given the Ctag file to analyze, return a list of (source_file, function, line_number)
    # Load JSON data from the file
    with open(ctag_file, 'r', errors="replace") as file:
        ctags_data = [json.loads(line) for line in file]
        # ctags_data = json.load(file)
    
    functions_list = []
    
    # Iterate through each entry in the ctags data
    for entry in ctags_data:
        if "kind" not in entry:
            continue
        if entry['kind'] in ['function', 'method']:
            file_name = entry['path']
            function_name = entry['name']
            line_number = entry['line']
            functions_list.append((file_name, function_name, line_number))
    
    return functions_list


def ident_source_function(function_nodes, line_number):
    # print(function_nodes)
    for func in function_nodes:
        # print(func)
        if func.end_line is None:
            if line_number >= func.start_line:
                return func
        else:
            if func.start_line <= line_number <= func.end_line:
                return func
    return None


def get_author(blame, file, line):
    # Given the blame set, return the author of the line and the Date/Time
    # print(blame)
    if file not in blame:
        return None
    if str(line) not in blame[file]:
        return None
    segment = blame[file][str(line)]
    return (segment['Author'], dateutil.parser.parse(segment['Date']))


def get_renames(path, rename_dir):
    # Given a path and the rename record filepath, return a list of all possible names
    with open(rename_dir, 'r') as file:
        for line in file:
            if path in line.strip().split(","):
                return line.strip().split(",")
    return path

def manage_snapshot_ops(snapshots, repo_path, extensions, vuln_schedule, blame_dir, call_dir, ctags_dir, rename_dir, invocation_out, collab_out):
    if "h" in extensions:
        extensions.remove("h")
    # filepath to file node
    path_node = {}
    # function to all files containing an instance
    function_lookups = {}
    # Large Author detail set 
    authorship_stats = {}
    blame = {}
    calls = {}

    header_string = "date, util_total, util_vuln_total, util_non_vuln_total, non_util_total, non_util_vuln_total, non_util_non_vuln_total, \
    util_total_calls, util_vuln_total_calls, util_non_vuln_total_calls, non_util_total_calls, non_util_vuln_total_calls, non_util_non_vuln_total_calls, \
    util_total_callers, util_vuln_total_callers, util_non_vuln_total_callers, non_util_total_callers, non_util_vuln_total_callers, non_util_non_vuln_total_callers, \
    average_callers_util, average_calls_util, average_callers_util_vuln, average_calls_util_vuln, average_callers_util_non_vuln, average_calls_util_non_vuln, \
    average_callers_non_util, average_calls_non_util, average_callers_non_util_vuln, average_calls_non_util_vuln, average_callers_non_util_non_vuln, average_calls_non_util_non_vuln"
    with open(invocation_out, 'w') as f:
        f.write(header_string)
        f.write("\n")

    # FAO, CAO, FTC, CTF, STC
    header_string = "date, FAO_util, CAO_util, FTC_util, CTF_util, STC_util, pct_FAO_util, pct_CAO_util, pct_FTC_util, pct_CTF_util, pct_STC_util, util_count, FAO_util_vuln, CAO_util_vuln, FTC_util_vuln, CTF_util_vuln, STC_util_vuln, pct_FAO_util_vuln, pct_CAO_util_vuln, pct_FTC_util_vuln, pct_CTF_util_vuln, pct_STC_util_vuln, util_vuln_count, FAO_util_non_vuln, CAO_util_non_vuln, FTC_util_non_vuln, CTF_util_non_vuln, STC_util_non_vuln, pct_FAO_util_non_vuln, pct_CAO_util_non_vuln, pct_FTC_util_non_vuln, pct_CTF_util_non_vuln, pct_STC_util_non_vuln, util_count_non_vuln, FAO_non_util, CAO_non_util, FTC_non_util, CTF_non_util, STC_non_util, pct_FAO_non_util, pct_CAO_non_util, pct_FTC_non_util, pct_CTF_non_util, pct_STC_non_util, non_util_count, FAO_non_util_vuln, CAO_non_util_vuln, FTC_non_util_vuln, CTF_non_util_vuln, STC_non_util_vuln, pct_FAO_non_util_vuln, pct_CAO_non_util_vuln, pct_FTC_non_util_vuln, pct_CTF_non_util_vuln, pct_STC_non_util_vuln, _non_util_vuln_count, FAO_non_util_non_vuln, CAO_non_util_non_vuln, FTC_non_util_non_vuln, CTF_non_util_non_vuln, STC_non_util_non_vuln, pct_FAO_non_util_non_vuln, pct_CAO_non_util_non_vuln, pct_FTC_non_util_non_vuln, pct_CTF_non_util_non_vuln, pct_STC_non_util_non_vuln, _non_util_non_vuln_count"
    with open(collab_out, 'w') as f:
        f.write(header_string)
        f.write("\n")

    # TEMP Debuggin
    flag=False

    # Loop over snapshots
    for snapshot in snapshots:
        path_node = {}
        function_lookups = {}
        date = snapshot[0]
        commit = snapshot[1]
        # Activate the snapshot
        snapshot_utils.activate_snapshot(repo_path, commit)
        # Build New Blame
        blame = build_current_blame(blame, f"{blame_dir}/{str(date).split()[0]}.json")
        # Build New Calls
        calls = build_current_calls(calls, f"{call_dir}/{str(date).split()[0]}.csv",repo_path)
        # Get Current Files
        all_current = snapshot_utils.get_current_files(repo_path, extensions)
        # Get Functions + Methods from CTags
        function_list = ident_ctag_functions(f"{ctags_dir}/{str(date).split()[0]}.json")
        # Build the Tree (currently not including functions)

        root = Node(None, "Directory", "ROOT", None, "", date)
        for file in all_current:
            parent = root
            if repo_path in file:
                path = file[len(repo_path) + 1:]
            else:
                path = file 
            if "test" in path.lower():
                continue
            segments = path.split("/")
            for index, segment in enumerate(segments):
                found = False
                for child in parent.children:
                    if child.name == segment:
                        found = True
                        parent = child
                        break
                if not found: 
                    temp_node = Node(parent, "File" if index == len(segments) - 1 else "Directory", segment, vuln_schedule[path] if path in vuln_schedule else None, path, date)
                    if temp_node.n_type == "File":
                        if path not in authorship_stats:
                            # Handle Renames
                            alt_names = get_renames(path, rename_dir)
                            renamed = False
                            for alt_name in alt_names:
                                if alt_name in authorship_stats:
                                    authorship_stats[path] = copy.deepcopy(authorship_stats[alt_name])
                                    renamed = True
                                    break
                            if not renamed:
                                authorship_stats[path]=dict()
                        path_node[path] = temp_node
                    parent.add_child(temp_node)
                    parent = temp_node

        # Add Functions/Methods to Tree & Add to Function Lookup Dictionary
        for func in function_list:
            file_name = func[0]
            function_name = func[1]
            line_number = func[2]
            if file_name in path_node:
                parent = path_node[file_name]
                temp_node = Node(parent, "Function", function_name, None, parent.full_path, date)
                temp_node.set_start(line_number)
                if function_name.startswith("anonymousFunction"):
                    continue
                parent.add_child(temp_node)
                if function_name not in authorship_stats[parent.full_path]:
                    authorship_stats[parent.full_path][function_name] = dict()
                if function_name in function_lookups and parent not in function_lookups[function_name]: # if the function is there, but the parent isn't in the list
                    function_lookups[function_name].append(parent)
                elif function_name in function_lookups and parent in function_lookups[function_name]: # if everything is there, do nothing
                    continue
                else: # if it is not there, set our parent as the only ones
                    function_lookups[function_name] = [parent]
            else:
                continue

        # Assign End Lines to Functions

        for host_file in path_node:
            temp = path_node[host_file]
            temp_children = []
            for entry in temp.children:
                if entry.n_type == "Function":
                    temp_children.append(entry)
            sorted_children = sorted(temp_children, key=lambda child: child.start_line)
            for i in range(len(sorted_children) - 1):
                sorted_children[i].end_line = sorted_children[i + 1].start_line - 1

        # Blame Lookups for every function in every node
        for host_file in path_node:
            for func in path_node[host_file].children:
                end = func.end_line if func.end_line is not None else 9999999
                for i in range(func.start_line, end + 1):
                    author_details = get_author(blame,host_file, i)
                    if author_details is None:
                        break
                    author = author_details[0]
                    author_date = author_details[1]
                    # Update Author Lookup with Blame data, replace any commit dates
                    if author in authorship_stats[host_file][func.name]:
                        current_date = authorship_stats[host_file][func.name][author][0]
                        if current_date is None or author_date < current_date:
                            authorship_stats[host_file][func.name][author][0] = author_date
                    else:
                        authorship_stats[host_file][func.name][author] = [author_date,None,None]

        # Remove from Author Lookup any funcitons not in tree
        temp_keys = []
        for file_path in authorship_stats:
            temp_keys.append(file_path)
        for file_path in temp_keys:
            if file_path not in path_node:
                del authorship_stats[file_path]
                continue
            function_keys = []
            for function_entry in authorship_stats[file_path]:
                function_keys.append(function_entry)
            for function_entry in function_keys:
                if function_entry not in function_lookups:
                    del authorship_stats[file_path][function_entry]
                    continue
                found = False
                for matching in function_lookups[function_entry]:
                    if matching.full_path == file_path:
                        found = True
                        break
                if not found:
                    del authorship_stats[file_path][function_entry]



        # Process Calls (if source path in tree)
        for call in calls:
            source = call[0]
            line = int(call[1])
            target = call[2]
            if source not in path_node:
                continue
            source_node = path_node[source]
            # Skip any targets that == "if", "for", "while"
            if target in ["if","for","while"]:
                continue
            # Check Valid In Tree
            if target not in function_lookups:
                continue
            # Determine Source Function
            source_function = ident_source_function(source_node.children, line)
            if source_function is None:
                continue
            # Blame Lookup for the Source Line 
            call_author_details = get_author(blame, source, line)
            if call_author_details is None:
                continue
            call_author = call_author_details[0]
            call_date = call_author_details[1]
            # Update Author Lookup


            # Same File Search, but if it == any start line, skip
            found_match = False
            for child in source_node.children:
                if child.name == target:
                    if child.start_line == line:
                        continue
                    found_match = True
                    child.add_caller(source_function)
                    source_function.add_call(child)
                    if call_author in authorship_stats[source_node.full_path][child.name]:
                        if  authorship_stats[source_node.full_path][child.name][call_author][1] is None or call_date < authorship_stats[source_node.full_path][child.name][call_author][1]:
                            authorship_stats[source_node.full_path][child.name][call_author][1] = call_date
                    else:
                        authorship_stats[source_node.full_path][child.name][call_author] = [None, call_date, None]
                    

            # Same Directory Search (source parent children)
            if not found_match:
                parent_dir = parent.parent
                for file in parent_dir.children:
                    if file == parent:
                        continue
                    if file.n_type != "File":
                        continue
                    for file_function in file.children:
                        if file_function.name == target:
                            found_match = True
                            file_function.add_caller(source_function)
                            source_function.add_call(file_function)
                            if call_author in authorship_stats[file.full_path][file_function.name]:
                                if authorship_stats[file.full_path][file_function.name][call_author][1] is None or call_date < authorship_stats[file.full_path][file_function.name][call_author][1]:
                                    authorship_stats[file.full_path][file_function.name][call_author][1] = call_date
                            else:
                                authorship_stats[file.full_path][file_function.name][call_author] = [None, call_date, None]

            # General Function Table Lookup
            if not found_match:
                matching_files = function_lookups[target]
                for file in matching_files:
                    if file == parent:
                        continue
                    for file_function in file.children:
                        if file_function.name == target:
                            found_match = True
                            file_function.add_caller(source_function)
                            source_function.add_call(file_function)
                            if call_author in authorship_stats[file.full_path][file_function.name]:
                                if authorship_stats[file.full_path][file_function.name][call_author][1] is None or call_date < authorship_stats[file.full_path][file_function.name][call_author][1]:
                                    authorship_stats[file.full_path][file_function.name][call_author][1] = call_date
                            else:
                                authorship_stats[file.full_path][file_function.name][call_author] = [None, call_date, None]



        # Invocation Statistic Generation
        util_total = 0
        util_vuln_total = 0
        util_non_vuln_total = 0
        non_util_total = 0
        non_util_vuln_total = 0
        non_util_non_vuln_total = 0

        util_total_calls = 0
        util_vuln_total_calls = 0
        util_non_vuln_total_calls = 0
        non_util_total_calls = 0
        non_util_vuln_total_calls = 0
        non_util_non_vuln_total_calls = 0

        util_total_callers = 0
        util_vuln_total_callers = 0
        util_non_vuln_total_callers = 0
        non_util_total_callers = 0
        non_util_vuln_total_callers = 0
        non_util_non_vuln_total_callers = 0

        for lookup_path in path_node:
            if path_node[lookup_path].util:
                if path_node[lookup_path].vuln:
                    util_total += 1
                    util_vuln_total += 1
                else:
                    util_total += 1
                    util_non_vuln_total += 1
            else:
                if path_node[lookup_path].vuln:
                    non_util_total += 1
                    non_util_vuln_total += 1
                else:
                    non_util_total += 1
                    non_util_non_vuln_total += 1
            for lookup_fun in path_node[lookup_path].children:
                if path_node[lookup_path].util:
                    if path_node[lookup_path].vuln:
                        util_total_callers += len(lookup_fun.callers)
                        util_total_calls += len(lookup_fun.calls)
                        util_vuln_total_callers += len(lookup_fun.callers)
                        util_vuln_total_calls += len(lookup_fun.calls)
                    else:
                        util_total_callers += len(lookup_fun.callers)
                        util_total_calls += len(lookup_fun.calls)
                        util_non_vuln_total_callers += len(lookup_fun.callers)
                        util_non_vuln_total_calls += len(lookup_fun.calls)
                else:
                    if path_node[lookup_path].vuln:
                        non_util_total_callers += len(lookup_fun.callers)
                        non_util_total_calls += len(lookup_fun.calls)
                        non_util_vuln_total_callers += len(lookup_fun.callers)
                        non_util_vuln_total_calls += len(lookup_fun.calls)
                    else:
                        non_util_total_callers += len(lookup_fun.callers)
                        non_util_total_calls += len(lookup_fun.calls)
                        non_util_non_vuln_total_callers += len(lookup_fun.callers)
                        non_util_non_vuln_total_calls += len(lookup_fun.calls)
        # Write Invocation Statistics to File
        try:
            average_callers_util = util_total_callers / util_total
        except:
             average_callers_util = 0
        try:
            average_calls_util = util_total_calls / util_total
        except:
            average_calls_util = 0
        try:
            average_callers_util_vuln = util_vuln_total_callers / util_vuln_total
        except:
            average_callers_util_vuln = 0
        try:
            average_calls_util_vuln = util_vuln_total_calls / util_vuln_total
        except:
            average_calls_util_vuln = 0
        try:
            average_callers_util_non_vuln = util_non_vuln_total_callers / util_non_vuln_total
        except:
            average_callers_util_non_vuln = 0
        try:
            average_calls_util_non_vuln = util_non_vuln_total_calls / util_non_vuln_total
        except:
            average_calls_util_non_vuln = 0

        try:
            average_callers_non_util = non_util_total_callers / non_util_total
        except:
            average_callers_non_util = 0
        try:
            average_calls_non_util = non_util_total_calls / non_util_total
        except:
            average_calls_non_util = 0
        try:
            average_callers_non_util_vuln = non_util_vuln_total_callers / non_util_vuln_total
        except:
            average_callers_non_util_vuln = 0
        try:
            average_calls_non_util_vuln = non_util_vuln_total_calls / non_util_vuln_total
        except:
            average_calls_non_util_vuln = 0
        try:
            average_callers_non_util_non_vuln = non_util_non_vuln_total_callers / non_util_non_vuln_total
        except:
            average_callers_non_util_non_vuln = 0
        try: 
            average_calls_non_util_non_vuln = non_util_non_vuln_total_calls / non_util_non_vuln_total
        except:
            average_calls_non_util_non_vuln = 0
        
        out_str = f"{str(date).split()[0]}, {util_total}, {util_vuln_total}, {util_non_vuln_total}, {non_util_total}, {non_util_vuln_total}, {non_util_non_vuln_total}, {util_total_calls}, {util_vuln_total_calls}, {util_non_vuln_total_calls}, {non_util_total_calls}, {non_util_vuln_total_calls}, {non_util_non_vuln_total_calls}, {util_total_callers}, {util_vuln_total_callers}, {util_non_vuln_total_callers}, {non_util_total_callers}, {non_util_vuln_total_callers}, {non_util_non_vuln_total_callers}, {average_callers_util}, {average_calls_util}, {average_callers_util_vuln}, {average_calls_util_vuln}, {average_callers_util_non_vuln}, {average_calls_util_non_vuln}, {average_callers_non_util}, {average_calls_non_util}, {average_callers_non_util_vuln}, {average_calls_non_util_vuln}, {average_callers_non_util_non_vuln}, {average_calls_non_util_non_vuln}"

        with open(invocation_out, 'a') as f:
            f.write(out_str)
            f.write("\n")

        # Author Profile Generation 
        # FAO, CAO, FTC, CTF, STC
        # Function Only, Call Only, Function Then Call, Call Then Function, Same Time
        util = [0,0,0,0,0]
        util_percent = []
        util_count = 0
        util_vuln = [0,0,0,0,0]
        util_vuln_percent = []
        util_vuln_count = 0
        util_non_vuln = [0,0,0,0,0]
        util_non_vuln_percent = []
        util_non_vuln_count = 0
        
        non_util = [0,0,0,0,0]
        non_util_percent = []
        non_util_count = 0
        non_util_vuln = [0,0,0,0,0]
        non_util_vuln_percent = []
        non_util_vuln_count = 0
        non_util_non_vuln = [0,0,0,0,0]
        non_util_non_vuln_percent = []
        non_util_non_vuln_count = 0

        # Contribute, Call
        for file in authorship_stats:
            for function in authorship_stats[file]:
                for author in authorship_stats[file][function]:
                    data = authorship_stats[file][function][author]
                    if data[0] is not None and data[1] is None:
                        index = 0
                    elif data[0] is None and data[1] is not None:
                        index = 1
                    elif data[0] < data[1]:
                        index = 2
                    elif data[0] > data[1]:
                        index = 3
                    else:
                        index = 4
                    temp_node = path_node[file]
                    if temp_node.util:
                        if temp_node.vuln:
                            util[index] += 1
                            util_count += 1
                            util_vuln[index] += 1
                            util_vuln_count += 1
                        else:
                            util[index] += 1
                            util_count += 1
                            util_non_vuln[index] += 1
                            util_non_vuln_count += 1
                    else:
                        if temp_node.vuln:
                            non_util[index] += 1
                            non_util_count += 1
                            non_util_vuln[index] += 1
                            non_util_vuln_count += 1
                        else:
                            non_util[index] += 1
                            non_util_count += 1
                            non_util_non_vuln[index] += 1
                            non_util_non_vuln_count += 1
        
        for item in util:
            try:
                util_percent.append(item/util_count)
            except:
                util_percent.append(0)
        for item in util_vuln:
            try:
                util_vuln_percent.append(item/util_vuln_count)
            except:
                util_vuln_percent.append(0)
        for item in util_non_vuln:
            try:
                util_non_vuln_percent.append(item/util_non_vuln_count)
            except:
                util_non_vuln_percent.append(0)
        
        for item in non_util:
            try:
                non_util_percent.append(item/non_util_count)
            except:
                non_util_percent.append(0)
        for item in non_util_vuln:
            try:
                non_util_vuln_percent.append(item/non_util_vuln_count)
            except:
                non_util_vuln_percent.append(0)
        for item in util_non_vuln:
            try:
                non_util_non_vuln_percent.append(item/non_util_non_vuln_count)
            except:
                non_util_non_vuln_percent.append(0)
        # Write File Author Profiles to File
        # Write File Author Statistics
        data = [[str(date).split()[0]] + util + util_percent + [util_count] + util_vuln + util_vuln_percent + [util_vuln_count] + util_non_vuln + util_non_vuln_percent + [util_non_vuln_count] + non_util + non_util_percent + [non_util_count] + non_util_vuln + non_util_vuln_percent + [non_util_vuln_count] + non_util_non_vuln + non_util_non_vuln_percent + [non_util_non_vuln_count]]

        with open(collab_out, 'a', newline='') as out_file:
            writer = csv.writer(out_file)
            writer.writerows(data)
    


def main():
    projects = ["django","FFmpeg","httpd", "linux", "struts", "systemd", "tomcat"]

    if len(sys.argv) > 1:
        projects = sys.argv[1:]


    for project in projects:
        # The path to the project's extensions file
        extensions_file = f"extensions/{project.lower()}.txt"
        # The selected commits path for snapshot navigtion
        commit_list = f"selected-commits/{project}.csv"
        extensions = snapshot_utils.load_extensions(extensions_file)
        # The path for accessing project renames
        renames = f"core-out/{project}/renames_files.txt"
        # The path for acessing project file vulnerability time mapping
        vuln_times = f"core-out/{project}/vuln_times.csv"
        vuln_schedule = snapshot_utils.get_vuln_schedule(vuln_times)
        # The path to the gathered blame data
        blame_dir = f"blame-data/{project}"
        # The path to the gathered function call details
        call_dir = f"calls-data/{project}"
        # The path to the collected ctags output
        ctags_dir = f"ctags/{project}"
        # The path to the local repository
        repo_path = f"Repo_Path/{project}"
        # The path where invocation data should be written
        invocation_out = f"usage-out/{project}_invocation_data.csv"
        # The path where collaboration data should be written
        collab_out = f"usage-out/{project}_collab_data.csv"

        snapshots = []
        with open(commit_list, 'r') as file:
            for line in file:
                sline = line.strip().split(",")
                date = datetime.strptime(sline[0], "%Y-%m-%d %H:%M:%S")
                commit = sline[1]
                snapshots.append((date,commit))
        snapshots.reverse()

        manage_snapshot_ops(snapshots,repo_path,extensions,vuln_schedule,blame_dir, call_dir, ctags_dir, renames, invocation_out, collab_out)


if __name__ == '__main__':
    main()