import snapshot_utils
import blame
from datetime import datetime

def main():
    projects = ["httpd", "struts", "systemd", "tomcat", "FFmpeg", "django", "linux"]

    for project in projects:
        commits = []
        # The path to the extensions file to read
        extensions_file = f"extensions/{project.lower()}.txt"
        # The path to the selected commits for snapshot navigation
        commit_list = f"selected-commits/{project}.csv"
        # The path where the repository of analysis is stored locally
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
            start = None
            end = None
            if i - 1 < 0:
                end = commits[0]
                # The path for output to be written to
                out_name = f"blame-data/{project}/{str(end[0]).split()[0]}.json"
                blame.build_data(out_name, None, end[1], extensions_file, local_path)
            else:
                start = commits[i - 1]
                end = commits[i]
                # The path for output to be written to
                out_name = f"blame-data/{project}/{str(end[0]).split()[0]}.json"
                blame.build_data(out_name, start[1], end[1], extensions_file, local_path)

if __name__ == '__main__':
    main()
