import subprocess

def process_complexity(local_repo, out_file):
    x = subprocess.getoutput(f"scc {local_repo} --by-file --format csv -o {out_file}")
    print(x)
