import time
import csv
import requests

# VirusTotal API key
API_KEY = "92573076e8d5eba01211f3d8a1a8c04ea5fac4c42f343220772fbe54c10c4228"

# VirusTotal API URL
url = "https://www.virustotal.com/vtapi/v2/file/report"

# CSV input and output filenames
input_csv = "codes.csv"
output_csv = "scan_results.csv"

# Scan hashes using VirusTotal and save results in CSV
with open(input_csv, "r") as infile, open(output_csv, "w", newline="") as outfile:
    reader = csv.DictReader(infile)
    fieldnames = ["Hash", "Positives"]
    writer = csv.DictWriter(outfile, fieldnames=fieldnames)
    writer.writeheader()

    for row in reader:
        hash_value = row["Hash"]

        params = {
            "apikey": API_KEY,
            "resource": hash_value
        }

        response = requests.get(url, params=params)
        json_response = response.json()

        if json_response.get("response_code") == 1:  # Success
            positives = json_response.get("positives")
            writer.writerow({"Hash": hash_value, "Positives": positives})
            print("Hash: {}".format(hash_value))
            print("Positives: {}".format(positives))
            print("-------------------------------------------")
        else:
            writer.writerow({"Hash": hash_value, "Positives": "Scan failed"})
            print("Scan failed for hash: {}".format(hash_value))
            print("-------------------------------------------")

        # Add a delay of 60 seconds between API calls
        time.sleep(15)
