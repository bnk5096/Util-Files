import snapshot_utils
from datetime import datetime
import prevalence
import complexity
import rename_ident
import vhp

def main():
    projects = ["httpd", "struts", "systemd", "tomcat", "FFmpeg", "django", "linux"]

    project_map = {"httpd":"HTTPD", "struts":"Struts", "systemd":"systemd", "tomcat":"Tomcat", "FFmpeg":"FFmpeg", "django":"Django", "linux":"Linux Kernel"}

    # The path to the vhp offender files JSON
    offender_files = f"vhp-records/offender_files.json"
    # The path to the directory containing the set of event data JSONs 
    event_dir = f"vhp-records/event-data"

    for project in projects:
        commits = []
        # The path to the extension file for the project
        extensions_file = f"extensions/{project.lower()}.txt"
        # The path to the selected commits for the project
        commit_list = f"selected-commits/{project}.csv"
        # the path to the local repository
        local_path = f"Repos/{project}"
        
        extensions = snapshot_utils.load_extensions(extensions_file)
        # The path to where all files for the project can be found
        all_files = f"core-out/{project}/all_files.txt"
        # THe path to where the files set of renames can be found
        renames = f"core-out/{project}/renames_files.txt"
        # The path to the vulnerability time mapping file
        vuln_times = f"core-out/{project}/vuln_times.csv"
        
        rename_ident.get_all_files(local_path, extensions, all_files)
        rename_ident.rename_ident(local_path, all_files, renames)
        rename_ident.vuln_check(renames, offender_files, project_map[project],event_dir, vuln_times)
        vuln_data = snapshot_utils.get_vuln_schedule(vuln_times)
        with open(commit_list, 'r') as file:
            for line in file:
                sline=line.strip().split(",")
                date = datetime.strptime(sline[0], "%Y-%m-%d %H:%M:%S")
                commit = sline[1]
                commits.append((date, commit))
        
        for commit in commits:
            date = commit[0]
            # The path where complexity output is to be written.
            complexity_out = f"complexity-out/{project}/{str(date).split()[0]}.csv"
            # The path where prevalence output data is to be written
            prevalence_out = f"prevalence-out/{project}.txt"
            snapshot_utils.activate_snapshot(local_path,commit[1])

            complexity.process_complexity(local_path, complexity_out)

            prevalence.determine_prevalence(local_path, extensions, vuln_data, date, prevalence_out)

if __name__ == '__main__':
    main()
