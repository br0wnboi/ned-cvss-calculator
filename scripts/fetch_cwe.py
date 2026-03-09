import os
import io
import csv
import json
import urllib.request
import zipfile
import re

# URL for MITRE CWE list (Research Concepts)
CWE_URL = "https://cwe.mitre.org/data/csv/1000.csv.zip"

def fetch_and_parse_cwe():
    target_json_path = os.path.join(os.path.dirname(__file__), "..", "data", "cwe-data.json")
    
    print(f"Downloading CWE data from {CWE_URL}...")
    try:
        response = urllib.request.urlopen(CWE_URL)
        zip_data = response.read()
    except Exception as e:
        print(f"Error downloading CWE data: {e}")
        return

    print("Extracting ZIP...")
    with zipfile.ZipFile(io.BytesIO(zip_data)) as z:
        # MITRE zip usually contains one csv file, let's find it.
        csv_filename = None
        for name in z.namelist():
            if name.endswith('.csv'):
                csv_filename = name
                break
                
        if not csv_filename:
            print("Could not find a CSV file in the downloaded ZIP.")
            return
            
        with z.open(csv_filename) as f:
            # MITRE CSVs often have version/header info in the first couple of lines
            # and might use a different encoding.
            # Convert bytes to string
            content = f.read().decode('utf-8', errors='replace')
            
            # The actual CSV data usually starts after standard CSV headers.
            # Example Headers: CWE-ID, Name, Description, etc.
            
            # Using csv.DictReader to parse
            lines = content.splitlines()
            
            # Sometimes MITRE CSVs have a comment line at the start or version info.
            # Let's skip until we find the header line.
            header_idx = -1
            for idx, line in enumerate(lines):
                if line.startswith('CWE-ID'):
                    header_idx = idx
                    break
                    
            if header_idx == -1:
                print("Could not find standard 'CWE-ID' column in CSV.")
                return
                
            csv_lines = lines[header_idx:]
            reader = csv.DictReader(csv_lines)
            
            parsed_data = []
            for row in reader:
                cwe_id = row.get('CWE-ID')
                name = row.get('Name')
                description = row.get('Description')
                extended_description = row.get('Extended Description')
                
                raw_alt_terms = row.get('Alternate Terms') or ""
                clean_alt_terms = ""
                
                if raw_alt_terms:
                    # Clean the raw string inline by replacing tags with newlines and labels
                    # MITRE format: ::TERM:Zip Slip:DESCRIPTION:some explanation::
                    cleaned = raw_alt_terms
                    
                    # Remove trailing ::
                    if cleaned.endswith("::"):
                        cleaned = cleaned[:-2]
                        
                    # Remove leading ::
                    if cleaned.startswith("::"):
                        cleaned = cleaned[2:]
                        
                    # Replace internal tags
                    cleaned = cleaned.replace("::TERM:", "\n- ")
                    cleaned = cleaned.replace("TERM:", "- ")
                    cleaned = cleaned.replace(":DESCRIPTION:", ": ")
                    
                    # Clean up multiple newlines or trailing spaces
                    clean_alt_terms = "\n".join([line.strip() for line in cleaned.splitlines() if line.strip()])
                
                alternate_terms = clean_alt_terms
                
                if cwe_id and name:
                    parsed_data.append({
                        "id": f"CWE-{cwe_id}",
                        "name": name,
                        "description": description or "",
                        "extended_description": extended_description or "",
                        "alternate_terms": alternate_terms
                    })
                    
            print(f"Parsed {len(parsed_data)} CWE entries.")
            
            print(f"Saving to {target_json_path}...")
            # Create data dir if it doesn't exist just in case
            os.makedirs(os.path.dirname(target_json_path), exist_ok=True)
            
            with open(target_json_path, 'w', encoding='utf-8') as out_f:
                json.dump(parsed_data, out_f) # Minified json
                
            print("Done!")

if __name__ == "__main__":
    fetch_and_parse_cwe()
