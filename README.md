
# GitHub Advisories Vulnerability Analyzer with KEV Matching

A comprehensive Python tool to fetch, parse, split, and analyze GitHub security advisories for the pip ecosystem with Known Exploited Vulnerabilities (KEV) matching.

## Features

- **Paginated Data Fetching**: Retrieves all GitHub advisories using pagination
- **CISA KEV Integration**: Fetches and matches against CISA Known Exploited Vulnerabilities
- **Severity Splitting**: Separates advisories by severity level into individual JSON files
- **Individual Zipping**: Creates separate zip files for each JSON file
- **KEV Matching**: Identifies which advisories are known exploited vulnerabilities
- **Data Parsing**: Extracts key vulnerability information
- **Table Generation**: Creates structured vulnerability tables
- **CSV Export**: Exports data to CSV format with KEV indicators
- **Analysis**: Provides statistical analysis and insights
- **Organized Output**: All files saved to an 'output' subdirectory

## Setup

1. Create a virtual environment
   `python3 -m venv gaf`
2. Activate virtual environment
   `source gaf/bin/activate`
3. Install dependencies
   ```pip install -r requirements.txt```

4. Set up environment variables:
   - Copy `.env.example` to `.env`
   - Add your GitHub API key to `.env`:

## Usage

Run the complete analysis:
`python main.py`

## Output Files

All files are saved to the `output/` subdirectory:

### JSON Files (5 files):
1. **output/advisories.json** - Original raw data from GitHub API (all pages)
2. **output/advisory_low.json** - Low severity advisories
3. **output/advisory_medium.json** - Medium severity advisories
4. **output/advisory_high.json** - High severity advisories
5. **output/advisory_critical.json** - Critical severity advisories

### ZIP Files (5 files):
1. **output/advisories.json.zip** - Zipped original data
2. **output/advisory_low.json.zip** - Zipped low severity advisories
3. **output/advisory_medium.json.zip** - Zipped medium severity advisories
4. **output/advisory_high.json.zip** - Zipped high severity advisories
5. **output/advisory_critical.json.zip** - Zipped critical severity advisories

### CSV Files (2 files):
1. **output/advisories.csv** - Structured CSV table with extracted fields and KEV matching
2. **output/known_exploited_vulnerabilities.csv** - CISA Known Exploited Vulnerabilities data

## Extracted Fields

For each vulnerability, the following information is extracted:

1. **cve_id** - CVE identifier
2. **ghsa_id** - GitHub Security Advisory ID
3. **summary** - Brief vulnerability summary
4. **description** - Detailed description (truncated to 200 chars)
5. **type** - Advisory type
6. **severity** - Severity level
7. **published_at** - Publication date
8. **updated_at** - Last update date
9. **github_reviewed_at** - GitHub review date
10. **KEV** - Known Exploited Vulnerability indicator (1 if matched, empty if not)

## Program Flow

1. **Create Output Directory**: Creates 'output' subdirectory
2. **Fetch Data**: Downloads all advisories from GitHub API using pagination
3. **Fetch CISA Data**: Downloads CISA Known Exploited Vulnerabilities
4. **Parse & Split**: Separates advisories by severity into individual files
5. **Individual Zipping**: Creates separate zip files for each JSON file
6. **Extract Information**: Extracts key fields from original data
7. **KEV Matching**: Matches CVE IDs against CISA KEV database
8. **Create Table**: Generates formatted vulnerability table with KEV status
9. **Export CSV**: Creates structured CSV file with KEV indicators
10. **Analyze**: Performs statistical analysis including KEV insights

## Analysis Features

- **Summary Statistics**: Count by severity and type
- **KEV Statistics**: Count and percentage of known exploited vulnerabilities
- **Time Analysis**: Publication date ranges
- **Recent Vulnerabilities**: Most recently published advisories
- **KEV Analysis**: Focus on most critical known exploited vulnerabilities
- **Formatted Display**: Clean console output with KEV indicators

## Pagination

The tool automatically handles GitHub API pagination:
- Uses `per_page=100` for maximum efficiency
- Follows `Link` headers to fetch all pages
- Displays progress for each page fetched
- Handles errors gracefully

## KEV Matching

The KEV matching process:
1. Fetches CISA Known Exploited Vulnerabilities CSV
2. Extracts CVE IDs from the CISA data
3. Matches against GitHub advisory CVE IDs
4. Marks matching advisories with KEV=1
5. Provides statistics on KEV matches

## GitHub API Key

To get a GitHub API key:
1. Go to GitHub Settings > Developer settings > Personal access tokens
2. Generate a new token with appropriate permissions
3. Add the token to your `.env` file

## File Structure

After running the program, you'll have:

```
<working dir>/
├── main.py
├── requirements.txt
├── .env
├── .env.example
├── README.md
└── output/
├── advisories.json # Original data (all pages)
├── advisories.json.zip # Zipped original data
├── advisory_low.json # Low severity advisories
├── advisory_low.json.zip # Zipped low severity advisories
├── advisory_medium.json # Medium severity advisories
├── advisory_medium.json.zip # Zipped medium severity advisories
├── advisory_high.json # High severity advisories
├── advisory_high.json.zip # Zipped high severity advisories
├── advisory_critical.json # Critical severity advisories
├── advisory_critical.json.zip # Zipped critical severity advisories
├── advisories.csv # Structured CSV table with KEV
└── known_exploited_vulnerabilities.csv # CISA KEV data
```

**Total: 12 files in output directory (5 JSON + 5 ZIP + 2 CSV)**
