import snapshot_utils
import subprocess
from functools import partial
from multiprocessing import Pool
import re
import json
import datetime


def get_git_blame(file_path, local_repo):
    out = subprocess.run(
        ["git", "blame", file_path],
        capture_output=True,
        text=False,
        cwd=local_repo
    )
    result = out.stdout.decode("utf-8", errors="replace")
    pattern = r"\((.+?)\s+(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\s+([\+\-]\d{4})\s+(\d+)\)"
    results = [file_path]
    results.append({})
    for line in result.split("\n"):
        find = re.search(pattern, line)
        if find:
            author = find.group(1).strip()
            date_str = find.group(2)
            time_str = find.group(3)
            offset = find.group(4)
            line_n = int(find.group(5))
            dt = datetime.datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M:%S")
            offset_hours = int(offset[:3]) 
            offset_minutes = int(offset[0] + offset[3:]) 
            tzinfo = datetime.timezone(datetime.timedelta(hours=offset_hours, minutes=offset_minutes))
            dt = dt.replace(tzinfo=tzinfo)
            results[1][line_n] = {"Author": author, "Date":str(dt)}
    return results



def process_file(local_repo, file_path):
    result = []
    try:
        result = get_git_blame(file_path, local_repo)
    except:
        print(f"ERROR OCCURRED on {file_path}")
    
    return result


def build_data(out_file, start_commit, end_commit, extensions_file, local_repo):
    extensions = snapshot_utils.load_extensions(extensions_file)
    if "h" in extensions:
        extensions.remove("h")
    all = snapshot_utils.get_current_files(local_repo, extensions)
    files = []
    if start_commit is None:
        files = all
    else:
        modified = snapshot_utils.get_modified_files(local_repo, extensions, start_commit, end_commit)
        for f in modified:
            if f in all:
                files.append(f)
    process_partial = partial(process_file, local_repo)
    with Pool(processes=10) as pool:
        with open(out_file, 'w') as file:
            for result in pool.imap_unordered(process_partial, files):
                key = result[0]
                value = result[1]
                entry = {key:value}
                json.dump(entry,file)
                file.write("\n")
