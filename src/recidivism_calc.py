"""Performs analysis based on previously generated recidivism reports. Manual Configuration required
"""
import matplotlib.pyplot as plt

def graph(util_type: list, util_mod: list, non_type: list, non_mod: list, x: list, project: str, scale: str) -> None:
    """Creates a line graph of each type of recidivism 

    Args:
        util_type (list): util type recidivism entry list
        util_mod (list): util module recidivism entry list
        non_type (list): non-util type recidivism entry list
        non_mod (list): non-util module recidivism entry list
        x (list): the list of labels for the X axis (Month/Quarter in the default case)
        project (str): the project name
        scale (str): the string description of the scale
    """
    plt.figure(figsize=(10,6))
    plt.plot(x, util_type, label="Util Type", marker='o')
    plt.plot(x, util_mod, label="Util Module", marker='s')
    # plt.plot(x, non_type, label="Non-Util Type", marker='^')
    # plt.plot(x, non_mod, label="Non-Util Module", marker='d')

    plt.xlabel("Snapshot")
    plt.ylabel("Recidivism Rate")
    plt.title(f"{project} Recidivism - {scale}-Day Scale")
    plt.legend()
    plt.savefig(f"{project}_{scale}_only_util.png")

def calc(path:str) -> tuple[list, list, list]:
    """Calculates recidivism numbers for graphing

    Args:
        path (str): the path to a recidivism report

    Returns:
        tuple[list, list, list]: type recidivism result list, module recidivism result list, x-axis labels (quarter/month id)
    """
    total_fixes = []
    type_recidivism = []
    module_recidivism = []
    result_type = []
    result_mod = []
    result_cap = []
    with open(path, 'r') as file:
        for line in file:
            if "Total Fixes:" in line:
                sline = line.strip().split("[")[1]
                sline2 = sline.split("]")[0]
                sline3 = sline2.split(", ")
                for entry in sline3:
                    total_fixes.append(float(entry))
            elif "Type Recidivism:" in line:
                sline = line.strip().split("[")[1]
                sline2 = sline.split("]")[0]
                sline3 = sline2.split(", ")
                for entry in sline3:
                    type_recidivism.append(float(entry))
            elif "Module Recidivism:" in line:
                sline = line.strip().split("[")[1]
                sline2 = sline.split("]")[0]
                sline3 = sline2.split(", ")
                for entry in sline3:
                    module_recidivism.append(float(entry))
    tot_fix = 0
    tot_m = 0
    tot_t = 0
    for i in range(len(total_fixes)):
        result_cap.append(i)
        # print("\n\nTime: ",i)
        # print("Type Recidivism:")
        if total_fixes[i] == 0:
            # print(0)
            result_type.append(0)
        else:
            tot_t += type_recidivism[i]
            # print(type_recidivism[i]/total_fixes[i])
            result_type.append(type_recidivism[i]/total_fixes[i])
        # print("Module Recidivism:")
        if total_fixes[i] == 0:
            # print(0)
            result_mod.append(0)
        else:
            tot_fix += total_fixes[i]
            tot_m += module_recidivism[i]
            # print(module_recidivism[i]/total_fixes[i])
            result_mod.append(module_recidivism[i]/total_fixes[i])
    print(f"\t\t\tModule Recidivism: {tot_m/tot_fix}")
    print(f"\t\t\tType Recidivism: {tot_t/tot_fix}")
    return result_type, result_mod, result_cap

def main():
    for size in ["30","90"]:
        print(f"Size: {size}")
        for project in ["Django", "FFmpeg", "HTTPD","Linux Kernel","Struts","systemd", "Tomcat"]:
            print(f"\tProject: {project}")
            print("\t\tUtils Only")
            # The path to the recidivism result data
            ut, um, uc = calc(f"recidivism-results/{project}_{size}_True.txt")
            print("\t\tNon-Utils Only")
            # The path to the recidivism result data
            nt, nm, _ = calc(f"recidivism-results/{project}_{size}_False.txt")
            graph(ut, um, nt, nm, uc, project, size)


if __name__ == '__main__':
    main()