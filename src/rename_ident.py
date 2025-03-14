from datetime import datetime
import subprocess
import csv
import json

def get_all_files(local_repo, extensions, out_file):
    command = f"git -C {local_repo} log --pretty=format: --name-only --no-renames | sort -u"
    file_string = subprocess.getoutput(command)
    file_list = file_string.split("\n")

    filtered_list = []
    for entry in file_list:
        if entry.split(".")[-1] in extensions:
            filtered_list.append(entry)

    with open(out_file, 'w') as file:
        for entry in filtered_list:
            file.write(f"{entry}\n")

    return filtered_list


def rename_ident(local_repo, all_files_path, out_file):
    # Get our list of valid files
    all_files = set()
    with open(all_files_path, 'r') as file:
        for line in file:
            all_files.add(line.strip())

    # Get the renamed set
    command = f"git -C {local_repo} log --pretty=format: --name-status --find-renames=50 --reverse | grep ^R"
    raw_rename_data = subprocess.getoutput(command)

    # Build our dictionary of old -> new
    # rename_mapping = {}
    rename_event_list = raw_rename_data.split("\n")
    duplicates = set()
    ever_new = set()
    chains = []
    rename_records = []
    for line in rename_event_list:
        split_line = line.split("\t")
        if len(split_line) != 3:
            continue
        old = split_line[1]
        new = split_line[2]
        flag = False
        for chain in chains:
            if old == chain[-1]:
                chain.append(new)
                duplicates.add(new)
                flag = True
                break
        if not flag:
            chains.append([old,new])
            duplicates.add(old)
            duplicates.add(new)
    for chain in chains:
        rename_records.append(tuple(chain))
    
    # Add non-renames to the central record
    for name in all_files:
        if name not in duplicates:
            rename_records.append(tuple([name]))
    
    # Write to a CSV file
    with open(out_file, 'w') as file:
        writer = csv.writer(file)
        for entry in rename_records:
            writer.writerow(entry)

    return rename_records
                    

def vuln_check(rename_record, offender_path, vhp_project, event_data_dir, out_file):
    vulnerable_paths = {}
    vulnerable_time = {}
    data = None
    format_string = "%Y-%m-%dT%H:%M:%S.%fZ"
    # Read in all offender files
    with open(offender_path, 'r') as file:
        data = json.load(file)
    
    # Determine all vulnerable paths for the given project
    for entry in data:
        if entry['project_name'] == vhp_project:
            vulnerable_paths[entry['filepath']] = []
            # Identify the CVEs related to the current filepath
            for cve in entry['cves']:
                vulnerable_paths[entry['filepath']].append(cve)
    # Loop through all identified paths
    for key in vulnerable_paths:
        earliest = None
        # Loop through CVEs associated with the filepath
        for cve in vulnerable_paths[key]:
            date_str = None
            # Read the event data for the current CVE
            with open(f"{event_data_dir}/{cve}.json", 'r') as file:
                event_data = json.load(file)
                # Loop through all events belonging to the CVE
                for event in event_data:
                    # Identify the Fix
                    if event['event_type'] == "fix":
                        date_str = event['date']
                        date = datetime.strptime(date_str, format_string)
                        break
            # See if the new date is earlier than any previous CVE
            if date_str is not None:
                if earliest is None or date < earliest:
                    earliest = date
                    vulnerable_time[key] = date

    vuln_record = {}
    # Read the rename records
    with open(rename_record, 'r') as file:
        for line in file:
            sline = line.strip().split(",")
            earliest = None
            # For every filename belonging to the unique file
            for entry in sline:
                # If the filename is in the vulnerable_time dictionary
                if entry in vulnerable_time:
                    # If the current filename has an earlier vulnerable date than the other file names
                    if earliest is None or vulnerable_time[entry] < earliest:
                        earliest = vulnerable_time[entry]
            # Assign each file name to the earliest time or "N/A" if there are no fix records associated
            for entry in sline:
                if earliest is None:
                    vuln_record[entry] = "N/A"
                else:
                    vuln_record[entry] = earliest
    # Write to the output file in the format file,vuln_time
    with open(out_file, "w") as file:
        for key in vuln_record:
            file.write(key + "," + str(vuln_record[key]) + "\n")
    
    return vuln_record
    

def promotion_records(rename_records, out_file):
    promotions = []
    demotions = []
    both = []
    promotions_nt = []
    demotions_nt = []
    both_nt = []
    with open(rename_records, 'r') as file:
        for line in rename_records:
            split_line = line.strip().split(",")
            if len(split_line) < 2:
                continue
            promote = False
            demote = False
            test = False
            prior_state = None
            for entry in split_line:
                if "test" in entry.lower():
                    test = True
                if prior_state is None:
                    if "util" in entry.lower() or "helper" in entry.lower():
                        prior_state = True
                    else:
                        prior_state = False
                elif prior_state:
                    # If we are already Util
                    if "util" in entry.lower() or "helper" in entry.lower():
                        prior_state = True
                    else:
                        prior_state = False
                        demote = True
                else:
                    # If we are not util
                    if "util" in entry.lower() or "helper" in entry.lower():
                        prior_state = True
                        promote = True
                    else:
                        prior_state = False
            
            # Build the appropriate lists
            if promote and demote:
                both.append(line)
                if not test:
                    both_nt.append(line)
            elif promote:
                promotions.append(line)
                if not test:
                    promotions_nt.append(test)
            elif demote:
                demotions.append(line)
                if not test:
                    demotions_nt.append(line)
    
    # Write output
    with open(out_file, 'w') as file:
        # Both
        file.write(f"Both (Tests Included). Total: {len(both)}\n")
        for line in both:
            file.write(f"{line}\n")

        # Promotions
        file.write(f"\nPromotions (Tests Included). Total: {len(promotions)}\n")
        for line in promotions:
            file.write(f"{line}\n")

        # Demotions
        file.write(f"\Demotions (Tests Included). Total: {len(demotions)}\n")
        for line in demotions:
            file.write(f"{line}\n")

        # Both NT
        file.write(f"\Both (Tests Excluded). Total: {len(both_nt)}\n")
        for line in both_nt:
            file.write(f"{line}\n")

        # Promotions NT
        file.write(f"\Promotions (Tests Excluded). Total: {len(promotions_nt)}\n")
        for line in promotions_nt:
            file.write(f"{line}\n")

        # Demotions NT
        file.write(f"\Demotions (Tests Excluded). Total: {len(demotions_nt)}\n")
        for line in demotions_nt:
            file.write(f"{line}\n")
