import snapshot_utils
from datetime import datetime
import re
import concurrent.futures

def get_function_calls(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='replace') as file:
        content = file.read()
    function_call_pattern = re.compile(r'\b(\w+\d*)\s*\(')
    calls = []
    for match in function_call_pattern.finditer(content):
        line_no = content.count('\n', 0, match.start()) + 1
        calls.append((file_path, line_no, match.group(1)))  # Only capture the function/method name
    return calls


def process(out_file, start_commit, end_commit, extensions_file, local_repo):
    extensions = snapshot_utils.load_extensions(extensions_file)
    if "h" in extensions:
        extensions.remove("h")
    all = snapshot_utils.get_current_files(local_repo, extensions)
    # print(all)
    files_pre = []
    if start_commit is None:
        files_pre = all
    else:
        modified = snapshot_utils.get_modified_files(local_repo, extensions, start_commit, end_commit)
        # print(modified)
        for f in modified:
            if f in all:
                files_pre.append(f)
    files = []
    for f in files_pre:
        files.append(f"{local_repo}/{f}")
    
    function_calls = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []
        for file in files:
            futures.append(executor.submit(get_function_calls, file))
        for future in concurrent.futures.as_completed(futures):
            function_calls.extend(future.result())
    return function_calls


def main():
    projects = ["httpd", "struts", "systemd", "tomcat", "FFmpeg", "django", "linux"]

    for project in projects:
        commits = []
        # The path of the extensions file for the project
        extensions_file = f"extensions/{project.lower()}.txt"
        # The selected commits to use for snapshot navigation
        commit_list = f"selected-commits/{project}.csv"
        # The path to the local repository
        local_path = f"Repos/{project}"
        
        with open(commit_list, 'r') as file:
            for line in file:
                sline=line.strip().split(",")
                date = datetime.strptime(sline[0], "%Y-%m-%d %H:%M:%S")
                commit = sline[1]
                commits.append((date, commit))
        commits.reverse()
        
        for i in range(len(commits) -1, -1, -1):
            snapshot_utils.activate_snapshot(local_path,commits[i][1])
            date = commits[i][0]
            start = None
            end = None
            if i - 1 < 0:
                end = commits[0]
                # The output path to write to
                out_name = f"calls-data/{project}/{str(end[0]).split()[0]}.csv"
                calls = process(out_name, None, end[1], extensions_file, local_path)
            else:
                start = commits[i - 1]
                end = commits[i]
                # The output path to write to
                out_name = f"calls-data/{project}/{str(end[0]).split()[0]}.csv"
                calls = process(out_name, start[1], end[1], extensions_file, local_path)
            
            with open(out_name,'w') as f:
                for call in calls:
                    source = call[0]
                    line_no = call[1]
                    target = call[2]
                    f.write(f"{source},{line_no},{target}\n")

if __name__ == '__main__':
    main()