"""Performs VHP API calls
"""
import requests
import json

def make_requests(vhp_dir):
    """Performs requests on the VHP API to fetch required data
    """
    
    # # Get Project data
    url = "https://vulnerabilityhistory.org/api/projects"
    response = requests.get(url)
    with open(f"{vhp_dir}/project_details.json", 'w') as file:
        json.dump(response.json(), file)

    # # Get all offender files
    url = "https://vulnerabilityhistory.org/api/filepaths"
    params = {
        "offenders":"true"
    }
    response = requests.get(url=url, params=params)
    with open(f"{vhp_dir}/offender_files.json", 'w') as file:
        json.dump(response.json(), file)

    # # Get Vulnerability Records
    url = "https://vulnerabilityhistory.org/api/vulnerabilities"
    response = requests.get(url=url)
    with open(f"{vhp_dir}/vulnerabilities_list.json", 'w') as file:
        json.dump(response.json(), file)

    # # Get Tag mapping to identify the CWEs
    url = "https://vulnerabilityhistory.org/api/tags"
    response = requests.get(url=url)
    with open(f"{vhp_dir}/tag_mapping.json", 'w') as file:
        json.dump(response.json(), file)

    # Get event dates for each CVE
    collection = None
    with open(f"{vhp_dir}/vulnerabilities_list.json", 'r') as file:
        collection = json.load(file)
    if collection is not None:
        for entry in collection:
            cve = entry['cve']
            url = f"https://vulnerabilityhistory.org/api/vulnerabilities/{cve}/events"
            response = requests.get(url)
            with open(f"{vhp_dir}/event-data/{cve}.json", 'w') as file:
                json.dump(response.json(), file)


def main():
    # The directory to put output files in
    make_requests("out_dir")


if __name__ == '__main__':
    main()