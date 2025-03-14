import snapshot_utils
from datetime import datetime
import subprocess

def main():
    projects = ["httpd", "struts", "systemd", "tomcat", "FFmpeg", "django", "linux"]

    for project in projects:
        commits = []
        # The path to the selected commits to use for snapshot navigation
        commit_list = f"selected-commits/{project}.csv"
        # The local path of the repository
        local_path = f"Repos/{project}"
        
        with open(commit_list, 'r') as file:
            for line in file:
                sline=line.strip().split(",")
                date = datetime.strptime(sline[0], "%Y-%m-%d %H:%M:%S")
                commit = sline[1]
                commits.append((date, commit))
        # commits.reverse()
        
        for i in range(len(commits) -1, -1, -1):
            snapshot_utils.activate_snapshot(local_path,commits[i][1])
            date = commits[i][0]
            # The path to use for output files
            output_file_path = f"ctags/{project}/{str(date).split()[0]}.json"
            command = f"ctags -R --links=no --fields=+n --output-format=json -o {output_file_path}"
            result = subprocess.run(command, shell=True, check=True, cwd=local_path)

if __name__ == '__main__':
    main()
