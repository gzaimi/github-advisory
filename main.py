import os
import requests
import json
import pandas as pd
import zipfile
from datetime import datetime
from dotenv import load_dotenv

def create_output_directory():
    """
    Create output directory if it doesn't exist
    """
    output_dir = 'output'
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"Created output directory: {output_dir}")
    return output_dir

def fetch_github_advisories():
    """
    Fetch GitHub security advisories for pip ecosystem with pagination and save to JSON file
    """
    # Load environment variables
    load_dotenv()
    
    # Get API key from environment
    api_key = os.getenv('GITHUB_API_KEY')
    if not api_key:
        raise ValueError("GITHUB_API_KEY not found in environment variables")
    
    # Headers
    headers = {
        'Accept': 'application/vnd.github+json',
        'Authorization': f'Bearer {api_key}'
    }
    
    # Parameters
    params = {
        'type': 'reviewed',
        'ecosystem': 'pip',
        'per_page': 100  # Maximum per page for efficiency
    }
    
    def get_next_page(page):
        """Check if there's a next page available"""
        return page if page.headers.get('link') is not None else None
    
    def search_github_advisories():
        """Generator function to fetch all pages of advisories"""
        session = requests.Session()
        
        # First page
        url = 'https://api.github.com/advisories'
        first_page = session.get(url, params=params, headers=headers)
        first_page.raise_for_status()
        yield first_page
        
        # Subsequent pages
        next_page = first_page
        while get_next_page(next_page) is not None:
            try:
                next_page_url = next_page.links['next']['url']
                next_page = session.get(next_page_url, headers=headers)
                next_page.raise_for_status()
                yield next_page
            except KeyError:
                print("No more GitHub pages")
                break
            except requests.exceptions.RequestException as e:
                print(f"Error fetching next page: {e}")
                break
    
    try:
        print("Fetching GitHub advisories with pagination...")
        all_advisories = []
        page_count = 0
        
        # Iterate through all pages
        for page in search_github_advisories():
            page_count += 1
            page_data = page.json()
            all_advisories.extend(page_data)
            print(f"Fetched page {page_count} with {len(page_data)} advisories")
        
        print(f"Successfully fetched {len(all_advisories)} advisories from {page_count} pages")
        
        # Create output directory and save to file
        output_dir = create_output_directory()
        output_file = os.path.join(output_dir, 'advisories.json')
        
        with open(output_file, 'w') as f:
            json.dump(all_advisories, f, indent=2)
        
        print(f"Data saved to {output_file}")
        return True
        
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data: {e}")
        return False
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON: {e}")
        return False

def fetch_cisa_kev_data():
    """
    Fetch CISA Known Exploited Vulnerabilities data and save as CSV
    """
    try:
        print("\nFetching CISA Known Exploited Vulnerabilities data...")
        
        url = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
        
        response = requests.get(url)
        response.raise_for_status()
        
        # Create output directory and save the CSV data
        output_dir = create_output_directory()
        output_file = os.path.join(output_dir, 'known_exploited_vulnerabilities.csv')
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(response.text)
        
        print(f"CISA KEV data saved to {output_file}")
        
        # Display some info about the data
        df_kev = pd.read_csv(output_file)
        print(f"Fetched {len(df_kev)} known exploited vulnerabilities")
        
        return True
        
    except requests.exceptions.RequestException as e:
        print(f"Error fetching CISA data: {e}")
        return False
    except Exception as e:
        print(f"Error processing CISA data: {e}")
        return False

def parse_and_split_advisories():
    """
    Parse advisories.json and split into separate files by severity,
    then zip each JSON file individually
    """
    try:
        output_dir = create_output_directory()
        advisories_file = os.path.join(output_dir, 'advisories.json')
        
        print(f"\nReading {advisories_file}...")
        with open(advisories_file, 'r') as f:
            advisories = json.load(f)
        
        print(f"Found {len(advisories)} advisories to parse and split")
        
        # Initialize dictionaries for each severity level
        severity_files = {
            'low': [],
            'medium': [],
            'high': [],
            'critical': []
        }
        
        # Categorize advisories by severity
        for advisory in advisories:
            severity = advisory.get('severity', 'unknown').lower()
            if severity in severity_files:
                severity_files[severity].append(advisory)
            else:
                print(f"Warning: Unknown severity '{severity}' for advisory {advisory.get('ghsa_id', 'unknown')}")
        
        # Create separate JSON files for each severity
        json_files = [os.path.join(output_dir, 'advisories.json')]  # Include original file
        
        for severity, advisories_list in severity_files.items():
            filename = os.path.join(output_dir, f'advisory_{severity}.json')
            with open(filename, 'w') as f:
                json.dump(advisories_list, f, indent=2)
            print(f"Created {filename} with {len(advisories_list)} advisories")
            json_files.append(filename)
        
        # Zip each JSON file individually
        print("\nCreating individual zip files...")
        zip_files = []
        
        for json_file in json_files:
            if os.path.exists(json_file):
                zip_filename = f"{json_file}.zip"
                with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
                    zipf.write(json_file, os.path.basename(json_file))
                print(f"Created {zip_filename}")
                zip_files.append(zip_filename)
        
        print(f"\nCreated {len(zip_files)} individual zip files")
        return True
        
    except FileNotFoundError:
        print("Error: advisories.json file not found. Please run the fetch function first.")
        return False
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON file: {e}")
        return False
    except Exception as e:
        print(f"Error creating split files or zips: {e}")
        return False

def extract_key_information():
    """
    Extract key information from advisories.json for table creation
    """
    try:
        output_dir = create_output_directory()
        advisories_file = os.path.join(output_dir, 'advisories.json')
        
        print(f"\nExtracting key information from {advisories_file}...")
        with open(advisories_file, 'r') as f:
            advisories = json.load(f)
        
        print(f"Processing {len(advisories)} advisories")
        
        # Initialize list to store extracted data
        extracted_data = []
        
        for advisory in advisories:
            # Extract required fields
            extracted_entry = {
                'cve_id': advisory.get('cve_id', 'N/A'),
                'ghsa_id': advisory.get('ghsa_id', 'N/A'),
                'summary': advisory.get('summary', 'N/A'),
                'description': advisory.get('description', 'N/A'),
                'type': advisory.get('type', 'N/A'),
                'severity': advisory.get('severity', 'N/A'),
                'published_at': advisory.get('published_at', 'N/A'),
                'updated_at': advisory.get('updated_at', 'N/A'),
                'github_reviewed_at': advisory.get('github_reviewed_at', 'N/A'),
                'KEV': ''  # Initialize KEV column
            }
            
            # Clean up description (remove newlines and limit length)
            if extracted_entry['description'] != 'N/A':
                extracted_entry['description'] = extracted_entry['description'].replace('\n', ' ').replace('\r', ' ')
                if len(extracted_entry['description']) > 200:
                    extracted_entry['description'] = extracted_entry['description'][:200] + "..."
            
            extracted_data.append(extracted_entry)
        
        print(f"Successfully extracted information from {len(extracted_data)} advisories")
        return extracted_data
        
    except FileNotFoundError:
        print("Error: advisories.json file not found.")
        return None
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON file: {e}")
        return None

def add_kev_matching(extracted_data):
    """
    Add KEV matching to the extracted data
    """
    try:
        print("\nAdding KEV matching...")
        
        output_dir = create_output_directory()
        kev_file = os.path.join(output_dir, 'known_exploited_vulnerabilities.csv')
        
        # Read CISA KEV data
        if not os.path.exists(kev_file):
            print("CISA KEV data not found. Skipping KEV matching.")
            return extracted_data
        
        df_kev = pd.read_csv(kev_file)
        
        # Extract CVE IDs from KEV data (assuming the column is named 'cveID' or similar)
        # Let's check the column names first
        print(f"CISA KEV columns: {list(df_kev.columns)}")
        
        # Find the CVE ID column (it might be 'cveID', 'CVE ID', etc.)
        cve_column = None
        for col in df_kev.columns:
            if 'cve' in col.lower():
                cve_column = col
                break
        
        if cve_column is None:
            print("Could not find CVE ID column in CISA data")
            return extracted_data
        
        print(f"Using CVE column: {cve_column}")
        kev_cves = set(df_kev[cve_column].dropna().astype(str))
        
        # Match CVE IDs
        matches = 0
        for entry in extracted_data:
            cve_id = entry['cve_id']
            if cve_id != 'N/A' and cve_id in kev_cves:
                entry['KEV'] = '1'
                matches += 1
        
        print(f"Found {matches} KEV matches out of {len(extracted_data)} advisories")
        return extracted_data
        
    except Exception as e:
        print(f"Error in KEV matching: {e}")
        return extracted_data

def create_vulnerability_table(extracted_data):
    """
    Create and display a formatted table of vulnerabilities
    """
    if not extracted_data:
        print("No data to create table")
        return None
    
    print(f"\n{'='*120}")
    print(f"{'VULNERABILITY ANALYSIS TABLE':^120}")
    print(f"{'='*120}")
    
    # Create DataFrame for better formatting
    df = pd.DataFrame(extracted_data)
    
    # Display summary statistics
    print(f"\nSUMMARY STATISTICS:")
    print(f"Total vulnerabilities: {len(df)}")
    print(f"Severity distribution:")
    severity_counts = df['severity'].value_counts()
    for severity, count in severity_counts.items():
        print(f"  {severity.capitalize()}: {count}")
    
    print(f"\nType distribution:")
    type_counts = df['type'].value_counts()
    for vuln_type, count in type_counts.items():
        print(f"  {vuln_type.capitalize()}: {count}")
    
    # KEV statistics
    kev_count = len(df[df['KEV'] == '1'])
    print(f"\nKEV Statistics:")
    print(f"  Known Exploited Vulnerabilities: {kev_count}")
    print(f"  KEV Percentage: {(kev_count/len(df)*100):.2f}%")
    
    # Display first 10 entries in a formatted table
    print(f"\n{'FIRST 10 VULNERABILITIES':^120}")
    print(f"{'='*120}")
    
    for i, row in df.head(10).iterrows():
        kev_status = "YES" if row['KEV'] == '1' else "NO"
        print(f"\n{i+1}. CVE ID: {row['cve_id']}")
        print(f"   GHSA ID: {row['ghsa_id']}")
        print(f"   Summary: {row['summary']}")
        print(f"   Description: {row['description']}")
        print(f"   Type: {row['type']} | Severity: {row['severity']} | KEV: {kev_status}")
        print(f"   Published: {row['published_at']}")
        print(f"   Updated: {row['updated_at']}")
        print(f"   GitHub Reviewed: {row['github_reviewed_at']}")
        print(f"   {'-'*100}")
    
    if len(df) > 10:
        print(f"\n... and {len(df) - 10} more vulnerabilities (see advisories.csv for complete data)")
    
    return df

def create_csv_file(extracted_data):
    """
    Create CSV file with extracted vulnerability information including KEV data
    """
    if not extracted_data:
        print("No data to create CSV file")
        return False
    
    try:
        print("\nCreating CSV file...")
        
        # Create DataFrame
        df = pd.DataFrame(extracted_data)
        
        # Create output directory and save to CSV
        output_dir = create_output_directory()
        csv_filename = os.path.join(output_dir, 'advisories.csv')
        
        df.to_csv(csv_filename, index=False)
        
        print(f"CSV file created: {csv_filename}")
        print(f"Contains {len(df)} advisories with {len(df.columns)} columns")
        
        # Display column information
        print(f"\nCSV Columns:")
        for i, col in enumerate(df.columns, 1):
            print(f"  {i}. {col}")
        
        # Show KEV statistics
        kev_count = len(df[df['KEV'] == '1'])
        print(f"\nKEV Summary:")
        print(f"  Total advisories: {len(df)}")
        print(f"  Known Exploited: {kev_count}")
        print(f"  KEV Percentage: {(kev_count/len(df)*100):.2f}%")
        
        return True
        
    except Exception as e:
        print(f"Error creating CSV file: {e}")
        return False

def analyze_vulnerabilities(extracted_data):
    """
    Perform additional analysis on the vulnerability data
    """
    if not extracted_data:
        return
    
    df = pd.DataFrame(extracted_data)
    
    print(f"\n{'='*60}")
    print(f"{'ADDITIONAL ANALYSIS':^60}")
    print(f"{'='*60}")
    
    # Convert date columns for analysis
    date_columns = ['published_at', 'updated_at', 'github_reviewed_at']
    for col in date_columns:
        df[col] = pd.to_datetime(df[col], errors='coerce')
    
    # Time analysis
    print(f"\nTIME ANALYSIS:")
    if not df['published_at'].isna().all():
        earliest_published = df['published_at'].min()
        latest_published = df['published_at'].max()
        print(f"Earliest published: {earliest_published}")
        print(f"Latest published: {latest_published}")
    
    # Most recent vulnerabilities
    print(f"\nMOST RECENT VULNERABILITIES (last 5):")
    recent_vulns = df.nlargest(5, 'published_at')
    for i, row in recent_vulns.iterrows():
        kev_status = "KEV" if row['KEV'] == '1' else ""
        print(f"  - {row['cve_id']}: {row['summary']} ({row['severity']}) {kev_status}")
    
    # KEV analysis
    print(f"\nKEV ANALYSIS:")
    kev_vulns = df[df['KEV'] == '1']
    if len(kev_vulns) > 0:
        print(f"Most critical KEV vulnerabilities:")
        for i, row in kev_vulns.head(5).iterrows():
            print(f"  - {row['cve_id']}: {row['summary']} ({row['severity']})")

def main():
    """
    Main program execution
    """
    print("GitHub Advisories Vulnerability Analyzer with KEV Matching")
    print("="*60)
    
    # Create output directory at the start
    output_dir = create_output_directory()
    
    # Step 1: Fetch data from GitHub API with pagination
    print("\nSTEP 1: Fetching data from GitHub API with pagination...")
    fetch_success = fetch_github_advisories()
    
    if not fetch_success:
        print("Failed to fetch data. Exiting.")
        return
    
    # Step 2: Fetch CISA KEV data
    print("\nSTEP 2: Fetching CISA Known Exploited Vulnerabilities data...")
    cisa_success = fetch_cisa_kev_data()
    
    if not cisa_success:
        print("Warning: Failed to fetch CISA data. Continuing without KEV matching.")
    
    # Step 3: Parse and split advisories by severity, zip each file individually
    print("\nSTEP 3: Parsing and splitting advisories by severity...")
    split_success = parse_and_split_advisories()
    
    if not split_success:
        print("Failed to parse and split data. Exiting.")
        return
    
    # Step 4: Extract key information
    print("\nSTEP 4: Extracting key information...")
    extracted_data = extract_key_information()
    
    if not extracted_data:
        print("Failed to extract data. Exiting.")
        return
    
    # Step 5: Add KEV matching
    print("\nSTEP 5: Adding KEV matching...")
    extracted_data = add_kev_matching(extracted_data)
    
    # Step 6: Create vulnerability table
    print("\nSTEP 6: Creating vulnerability analysis table...")
    df = create_vulnerability_table(extracted_data)
    
    # Step 7: Create CSV file
    print("\nSTEP 7: Creating CSV file...")
    csv_success = create_csv_file(extracted_data)
    
    # Step 8: Additional analysis
    print("\nSTEP 8: Performing additional analysis...")
    analyze_vulnerabilities(extracted_data)
    
    print(f"\n{'='*60}")
    print("Analysis complete! All files saved to the 'output' directory:")
    print(f"\nOutput directory: {os.path.abspath(output_dir)}")
    print("\nJSON Files:")
    print("- output/advisories.json (original raw data)")
    print("- output/advisory_low.json (low severity advisories)")
    print("- output/advisory_medium.json (medium severity advisories)")
    print("- output/advisory_high.json (high severity advisories)")
    print("- output/advisory_critical.json (critical severity advisories)")
    print("\nZIP Files:")
    print("- output/advisories.json.zip")
    print("- output/advisory_low.json.zip")
    print("- output/advisory_medium.json.zip")
    print("- output/advisory_high.json.zip")
    print("- output/advisory_critical.json.zip")
    print("\nCSV Files:")
    print("- output/advisories.csv (structured table with KEV matching)")
    print("- output/known_exploited_vulnerabilities.csv (CISA KEV data)")

if __name__ == "__main__":
    main()