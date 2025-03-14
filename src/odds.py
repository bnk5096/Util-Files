import csv

def calculate_odds_ratio(row):
    try:
        result = (float(row[1]) / float(row[2])) / (float(row[3]) / float(row[4]))
    except ZeroDivisionError:
        result = 0
    except ValueError:
        result = 0
    return result

def calculate_odds_ratio_nt(row):
    try:
        result = (float(row[6]) / float(row[7])) / (float(row[8]) / float(row[9]))
    except ZeroDivisionError:
        result = 0
    except ValueError:
        result = 0
    return result

def process_csv(input_file, output_file):
    with open(input_file, mode='r') as infile, open(output_file, mode='w', newline='') as outfile:
        reader = csv.reader(infile)
        writer = csv.writer(outfile)

        for row in reader:
            if len(row) > 9:
                row[5] = calculate_odds_ratio(row)
                row[10] = calculate_odds_ratio_nt(row)
                writer.writerow(row)

# Provide the directory and filename for the input and output files

def main():
    projects = ["django","FFmpeg","httpd", "linux", "struts", "systemd", "tomcat"] 
    for project in projects:
        # The prevalence data to read from
        input_csv_path = f'prevalence-out\\{project}.csv'
        # The output path for odds ratio data
        output_csv_path = f'odds-ratios-out\\{project}.csv'
        process_csv(input_csv_path, output_csv_path)



if __name__ == '__main__':
    main()
