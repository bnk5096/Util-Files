import snapshot_utils

def determine_prevalence(local_repo, extensions, vuln_dates, date, out_file):
    current_files = snapshot_utils.get_current_files(local_repo, extensions)
    vulnerable_util_count = 0
    vulnerable_non_util_count = 0
    non_vulnerable_util_count = 0
    non_vulnerable_non_util_count = 0

    vulnerable_util_nt = 0
    vulnerable_non_util_nt = 0
    non_vulnerable_util_nt = 0
    non_vulnerable_non_util_nt = 0

    for file in current_files:
        if "util" in file.lower() or "helper" in file.lower():
            if file not in vuln_dates or date < vuln_dates[file]:
                non_vulnerable_util_count += 1
                if "test" not in file.lower():
                    non_vulnerable_util_nt += 1
                continue
            if file in vuln_dates and date >= vuln_dates[file]:
                vulnerable_util_count += 1
                if "test" not in file.lower():
                    vulnerable_util_nt += 1
                continue
        else:
            if file not in vuln_dates or date < vuln_dates[file]:
                non_vulnerable_non_util_count += 1
                if "test" not in file.lower():
                    non_vulnerable_non_util_nt += 1
                continue
            if file in vuln_dates and date >= vuln_dates[file]:
                vulnerable_non_util_count += 1
                if "test" not in file.lower():
                    vulnerable_non_util_nt += 1
                continue
    
    # Write to Output 
    with open(out_file, 'a') as file:
        # Log Date
        file.write(str(date) + ",")
        # Log W/Tests
        file.write(f"{vulnerable_util_count},{non_vulnerable_util_count},{vulnerable_non_util_count}, {non_vulnerable_non_util_count},")
        try:
            file.write(f"{(vulnerable_util_count + non_vulnerable_util_count)/(vulnerable_non_util_count + non_vulnerable_non_util_count + vulnerable_util_count + non_vulnerable_util_count)},")
        except:
            file.write("ERROR,")
        # Log W/out Tests
        file.write(f"{vulnerable_util_nt},{non_vulnerable_util_nt},{vulnerable_non_util_nt}, {non_vulnerable_non_util_nt},")
        try:
            file.write(f"{(vulnerable_util_nt + non_vulnerable_util_nt)/(vulnerable_non_util_nt + non_vulnerable_non_util_nt + vulnerable_util_nt + non_vulnerable_util_nt)}")
        except:
            file.write("ERROR")
        # New Line
        file.write("\n")
                    