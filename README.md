# Util-Files
The scripts and data provided in this repository are intended for use with submission #1854
## Directory Structure
- src - all of the scripts used in our data processing
- selected-commits - the commits we checked out to perform our analysis on
- usage-results - Two CSV files for each project analyzed. One containing the recorded collaboration data, the other measurements on the calls to and from functions in the project
- promotion-records - The results of our file renaming analysis as it relates to files gaining and losing the "util" convention
- prevalence-out - the results of our prevalence analysis provided as CSV files
- extensions - lists of valid source  code file extensions for each project
- core-out - This directory is further divided into sub directories for each project. Each project includes a list of all located files, a set of all files with renames taken into consideration, and a csv that details for each file, the time after which we have considered a file to be vulnerable based on the first time a commit repairing a vulnerability was made to that file
- complexity-simplified - This directory contains combined complexity data for each project in place of the full SCC reports for each commit we take measurements at.
- renames - This is a combined directory of rename data useful for some of the provided scripts
- recidivism-results - This is a directory containing our collected recidivism data for each project
- odds-ratios-out - This directory contains our results from odds ratio calculations
 
## Provided Scripts & Running Instructions
- vhp.py
  - This script is used to access the required API information from the Vulnerability History Project. These records are required for much of the process we employ and it is recommened that this script be ran first.
  - It can be configured by updating the intended output directory within the script
  - Additionally, the output directory must contain a subdirectory named "event-data" as the individual vulnerability event logs will be written here
- snapshot_utils.py
  - This script is a utility file used by the other scripts in this repository. It contains functionality related to collecting all files present in a commit, checking out a commit, and building a new set of commits for analysis.
- rename_ident.py
  - This script includes functionaltiy for navigating renamed files in the projects of analysis. It is utilized by other scripts for their analysis.
  - It further is used for generating results for RQ 1.3
- recidivism_calc.py
  - This script performs analysis on the reports generated by recidivism.py for RQ 4.2 and generates an accompanying matplotlib graph
  - The main function must be configured to include required paths
- recidivism.py 
  - This script generates raw recidivism reports for use by recidivisim_calc.py for RQ 4.2
  - The main function must be updated to include the correct paths for requisite data
- prevalence.py
  - This script contains the functionality for answering our RQ 1.1. It contains a function used in complexity_prevalence.py for constructing the CSV of prevalence data that we provided in prevalence-out
- odds.py
  - This script is used to generate odds ratios for RQ RQ 4.1
  - The main function must be updated to reflect correct pathing
- invocation_tress.py
  - This script contains the functionality for analyzing the functions and function calls of util files as it relates to RQ 1.2 and RQ 3 of our submission.
  - It must be configured for operation. The main function includes several variables pointing to the location of certain data, where output should be written to, and the path to the repo under analysis. These values must be populated to reflect the local file structure prior to operation
- cwe.py
  - This script identifies the most common CWEs out of the Vulnerability History Project Data for RQ 4.3
  - The main function must be updated to incldue accurrate paths to requisite date 
  - Operation will be easiest if the rename files from core-out are copied into a new directory of just rename files
- ctags.py
  - This script navigates all selected commits and runs universal ctags in order to locate functions for later processing for RQs 1.2 and 3
  - The main function must be configured with changes to path variables to properly reflect directory structure
- complexity.py
  - This script contains a single function used to gather complexity data via the running of scc for RQ 2.
- complexity_prevalence.py
  - This script manages the running of functions from the complexity and prevalence scripts for RQ 1.1 and RQ 2.
  - This script must be configured to point to the correct directories.
- call_locate.py
  - This script handles the locating of function calls in a given repository. This data is used for RQ 1.2 and RQ 3.
  - The main function must be configured to include paths to the diresired output location and the location of requisite data
- blame.py
  - This script handles git blame operations for use in RQ 3.
- blame_runner.py
  - This script manages the selection of commits for blame operations for RQ3.
  - This script must be configured in the main function to reflect the intended data paths and output locations.
  