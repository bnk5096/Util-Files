"""Generates recidivism reports. Requires some manual configuration
"""
import json
from operator import attrgetter
from typing import List
from datetime import datetime, timedelta

class CVE:
    def __init__(self, id: str, cwe_list: List[str], project: str, date: datetime):
        self.id = id
        self.cwe_list = cwe_list
        self.project = project
        self.date = date
        self.files = set()
        self.util = False
    
    def add_file(self, file):
        self.files.add(file)

    def set_util(self):
        self.util = True

def read_vulns(vuln_list: str, tag_map: dict, event_data_dir: str, off_files:str, util_map:dict) -> list:
    """generates a list of CVE objects to use in analysis

    Args:
        vuln_list (str): the path to the VHP vulnerability records
        tag_map (dict): a map of tags to CWEs
        event_data_dir (str): the path to the VHP event records
        off_files (str): the path to the known offenders file
        util_map (dict): a map of files to their util status

    Returns:
        list: a list of generated CVE objects
    """
    results = []
    data = None
    format_string = "%Y-%m-%dT%H:%M:%S.%fZ"
    with open(vuln_list, 'r') as file:
        data = json.load(file)
    for entry in data:
        cwes = []
        id = entry['cve']
        project = entry['project_name']
        if project == "Chromium":
            continue
        for tag in entry['tag_json']:
            if tag['id'] in tag_map:
                cwes.append(tag_map[tag['id']])
        date_str = None
        with open(f"{event_data_dir}/{id}.json") as file:
            event_data = json.load(file)
            for event in event_data:
                if event['event_type'] == "fix":
                    date_str = event['date'] 
                    date = datetime.strptime(date_str, format_string)
                    break
        if date_str is not None:
            results.append(CVE(id, cwes, project, date))
    file_cve_map = {}
    with open(off_files, 'r') as file:
        file_set = json.load(file)
        for file in file_set:
            path = file['filepath']
            for cve in file['cves']:
                if cve not in file_cve_map:
                    file_cve_map[cve] = []
                file_cve_map[cve].append(path)
    for entry_loc in range(len(results)):
        entry = results[entry_loc].id
        if entry in file_cve_map:
            for f in file_cve_map[entry]:
                results[entry_loc].add_file(f)
    for entry in results:
        project = entry.project
        if project == "Chromium":
            continue
        for file in entry.files:
            if file in util_map[project] and util_map[project][file] == True:
                print(file)
                entry.set_util()
                break
    return results
            
        

def get_tag_cwes(tag_map_file: str) -> dict:
    """generates a map of tag IDs to CWE numbers

    Args:
        tag_map_file (str): the file to the VHP tag data

    Returns:
        dict: a dictionary mapping VHP Tag IDs to CWEs
    """
    created_map = {}
    data = None
    with open(tag_map_file, 'r') as file:
         data = json.load(file)
    for entry in data:
        if 'cwe' in entry['shortname'].lower():
            created_map[entry["id"]] = entry['shortname']
    return created_map

def get_util(rename_dir: str) -> dict:
    """Builds a map of files to their util status

    Args:
        rename_dir (str): path to the directory containing the rename records

    Returns:
        dict: a map of files to their util status
    """
    project_map = {'django.csv':"Django",'FFmpeg.csv':"FFmpeg",'httpd.csv':"HTTPD",'linux.csv':"Linux Kernel",'struts.csv':"Struts",'systemd.csv':"systemd",'tomcat.csv':"Tomcat"}
    util_map = {}
    for rename_file in ['django.csv','FFmpeg.csv','httpd.csv','linux.csv','struts.csv','systemd.csv','tomcat.csv']:
        project = project_map[rename_file]
        util_map[project] = dict()
        print(f"ADDED Project: {project}")
        with open(f"{rename_dir}/{rename_file}", 'r') as file:
            for line in file:
                if "util" in line.lower() or "helper" in line.lower():
                    for entry in line.strip().split(","):
                        util_map[project][entry] = True
                else:
                    for entry in line.strip().split(","):
                        util_map[project][entry] = False
    return util_map

def get_date_tuples(lst):
     return [(lst[i], lst[i+1]) for i in range(len(lst)-1)]

def create_expanded_tuples(date_list):
    blocks = [date_list[i:i+3] for i in range(0, len(date_list), 3)]
    ninety_day = [(block[0][0], block[-1][-1]) for block in blocks]
    return ninety_day

def get_selected(selected_dir):
    project_map = {'django.csv':"Django",'FFmpeg.csv':"FFmpeg",'httpd.csv':"HTTPD",'linux.csv':"Linux Kernel",'struts.csv':"Struts",'systemd.csv':"systemd",'tomcat.csv':"Tomcat"}
    date_map = {}
    for commit_file in ['django.csv','FFmpeg.csv','httpd.csv','linux.csv','struts.csv','systemd.csv','tomcat.csv']:
        temp_data = list()
        date_map[project_map[commit_file]] = []
        with open(f"{selected_dir}/{commit_file}", 'r') as file:
            for line in file:
                sline = line.strip().split(",")
                if len(sline) != 2:
                    continue
                date_str = sline[0]
                temp_data.append(datetime.strptime(date_str,"%Y-%m-%d %H:%M:%S"))
            temp_data.reverse()
            date_map[project_map[commit_file]] = get_date_tuples(temp_data)
            # date_map[project_map[commit_file].reverse()]
    return date_map



def calc_metrics(cve_obj_list: list, out_dir: str, date_map) -> None:
    """Builds the recivism reports

    Args:
        cve_obj_list (list): the list of generated CVE objects
        out_dir (str): the file to write to
    """
    by_project = {}
    for cve in cve_obj_list:
        if cve.project not in by_project:
            by_project[cve.project] = [cve]
        else:
            by_project[cve.project].append(cve)
    for status in [True, False, "ALL"]:
        for project in by_project:
            for day_count in [30,90]:
                date_tuples = date_map[project]
                if day_count == 90:
                    date_tuples = create_expanded_tuples(date_map[project])
                seen_cwe = set()
                seen_file = set()
                module_r = []
                module_repeats = []
                type_r = []
                type_repeats = []
                fixed = []
                sorted_data = sorted(by_project[project], key=attrgetter('date'))
                # start = sorted_data[0].date
                # while start < datetime.now():
                for date_pair in date_tuples:
                    # end = start + timedelta(days=day_count)
                    start = date_pair[0]
                    end = date_pair[1]
                    temp_module = 0
                    temp_type = 0
                    temp_total = 0 
                    for entry in sorted_data:
                        if status == True and entry.util == False:
                            continue
                        if status == False and entry.util == True:
                            continue
                        if entry.date < start:
                            continue
                        if entry.date > end:
                            break
                        temp_total += 1
                        old_t = temp_type
                        for cwe in entry.cwe_list:
                            if cwe in seen_cwe:
                                if old_t == temp_type:
                                    temp_type += 1
                                type_repeats.append(cwe)
                            else:
                                seen_cwe.add(cwe)
                        old_m = temp_module
                        for module in entry.files:
                            if module in seen_file:
                                if old_m == temp_module:
                                    temp_module += 1
                                module_repeats.append(module)
                            else:
                                seen_file.add(module)

                    type_r.append(temp_type)
                    module_r.append(temp_module)
                    fixed.append(temp_total)
                    # start = end + timedelta(microseconds=1)
                with open(f"{out_dir}/{project}_{day_count}_{status}.txt", 'w') as file:
                    file.write(f"{project} {day_count}-day interval\n")
                    file.write(f"Status: {status}\n")
                    file.write(f"Total Fixes: {fixed}\n")
                    file.write(f"Type Recidivism: {type_r}\n")
                    file.write(f"Repeated Types: {type_repeats}\n")
                    file.write(f"Module Recidivism: {module_r}\n")
                    file.write(f"Repeated Modules: {module_repeats}\n")
                    

def main():
    # The path containing selected commits
    selected_dir = f"selected-commits"
    date_map = get_selected(selected_dir)
    # The path to the tag mapping data from the VHP
    tag_map = get_tag_cwes("vhp-records/tag_mapping.json")
    # the path of the rename directory
    util_map = get_util("renames")
    # The first argument is the path to the vulnerability list JSON from the VHP
    # The third arugment is the path to the directory containing VHP event data
    # The fourth argumente is the path to the offender files JOSN from the VHP
    results = read_vulns("vhp-records/vulnerabilities_list.json", tag_map, "vhp-records/event-data", "vhp-records/offender_files.json", util_map)
    calc_metrics(results, "recidivism-results", date_map)


if __name__ == "__main__":
    main()