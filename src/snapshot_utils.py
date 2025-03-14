import subprocess
import requests
import os
from datetime import datetime, timedelta
from git import Repo

def select_commits(local_repo, owner, repo, auth, out_file):
    pathway = []
    repo = Repo(local_repo)
    init_commit = next(repo.iter_commits(reverse=True))
    first_date = datetime.fromtimestamp(init_commit.committed_date)
    new_date = datetime(first_date.year, first_date.month, first_date.day)
    print(init_commit.hexsha)
    pathway.append((str(new_date),str(init_commit.hexsha)))
    target_date = new_date
    with open(auth, 'r') as file:
        auth = file.readline().strip()
    while target_date < datetime.now():
        target_date = target_date + timedelta(days=30)
        since = target_date.isoformat() + "Z"
        until = (target_date + timedelta(days=1) - timedelta(microseconds=1)).isoformat() + "Z"
        url = f"https://api.github.com/repos/{owner}/{repo}/commits"
        params = {
            'since': since,
            'until': until
        }
        headers = {
            'Authorization':f'Bearer {auth}',
            'X-GitHub-Api-Version': '2022-11-28'
            }
        response = requests.get(url=url, headers=headers, params=params)

        if response.status_code == 200:
            commits = response.json()
            if not commits:
                target_date = target_date - timedelta(days=29)
            else:
                new_commit = commits[0]['sha']
                pathway.insert(0,(str(target_date), str(new_commit)))
        # If we get nothing back, add 1 day, try again, repeat until we get a result
        else:
            print(response.status_code)
            break
    with open(out_file, 'w') as file:
        for entry in pathway:
            file.write(entry[0] + "," + entry[1] + "\n")


def activate_snapshot(repo, commit):
    subprocess.getoutput(f"git -C {repo} checkout {commit}")
    subprocess.getoutput(f"git -C {repo} pull")


def get_current_files(local_repo, extensions):
    file_list = []
    for root, _, files in os.walk(local_repo):
        for file in files:
            if file.split(".")[-1] not in extensions:
                continue
            file_list.append(os.path.join(root, file)[len(local_repo) + 1:])
    return file_list

def get_current_files_fp(local_repo, extensions):
    file_list = []
    for root, _, files in os.walk(local_repo):
        for file in files:
            if file.split(".")[-1] not in extensions:
                continue
            file_list.append(os.path.join(root, file))
    return file_list


def get_modified_files(local_repo, extensions, older_commit, newer_commit):
    results = []
    modified = subprocess.getoutput(f"git -C {local_repo} diff --name-only --no-renames {older_commit} {newer_commit}")
    for file in modified.split("\n"):
        if file.split(".")[-1] in extensions:
            results.append(file.strip())
    return results


def load_extensions(extensions_file):
    extensions = set()
    with open(extensions_file, 'r') as file:
        for line in file:
            extensions.add(line.strip())
    return extensions


def get_vuln_schedule(vulnerability_times):
    vuln = {}
    with open(vulnerability_times, 'r') as file:
        for line in file:
            lines = line.strip().split(",")
            status = lines[-1]
            vpath = lines[0]
            if status == "N/A":
                continue
            else:
                vuln[vpath] = datetime.strptime(status, "%Y-%m-%d %H:%M:%S")
    return vuln 