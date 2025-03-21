# Link Extractor

A tool for extracting domains from websites.

## Overview

Link Extractor is a Python tool that scrapes a specified webpage, extracts script tags and PHP files, analyzes JavaScript and PHP files, and identifies domains referenced within them. It helps security researchers and web developers identify external dependencies and potential security risks in websites.

## Features

- Extracts domains from JavaScript and PHP files
- Identifies embedded domains in source code
- Tracks domains across multiple scans
- Maintains a database of found domains
- Supports filtering through exception list
- Detects potential tracking domains

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/link-extractor.git
   cd link-extractor
   ```

2. Install the dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Make the script an executable (linux)
```
chmod +x link_extractor.py
```

## Usage

### Analyzing a Single URL

```
python link_extractor.py --url https://example.com
```

### Processing Multiple Domains from a File

```
python link_extractor.py --file domains.txt
```

The file should contain one domain per line. Lines starting with `#` are treated as comments and ignored.

### Listing Domains from the Database

```
python link_extractor.py --list
```

By default, domains are listed in ascending order by occurrences. Use `--desc` to sort in descending order:

```
python link_extractor.py --list --desc
```

### Command-line Arguments

```
python link_extractor.py [-h] [--url URL] [--file FILE] [--list] [-v] [--asc] [--desc]
```

Arguments:
- `--url URL` - The target website URL to analyze
- `--file FILE, -f FILE` - Process domains from a file (one domain per line)
- `--list, -l` - List all domains in the database
- `-v, --verbose` - Display detailed output including all scripts found
- `--asc` - Sort domains in ascending order (used with --list)
- `--desc` - Sort domains in descending order (used with --list)
- `--with-head, -wh` - Lets the script open a browser window instead of running headless
- `-h, --help` - Display usage information

## Configuration

The tool uses two configuration files:
- `exceptions.txt` - List of domains to ignore (one domain per line)
- `explored_urls.txt` - List of already explored domains with dates

## Database

The tool stores found domains in an SQLite database (`domains.db`). The database contains the following information:
- Domain name
- Number of occurrences
- Whether the domain is likely a tracker
- Origin URLs where the domain was found

## Project Structure

```
link-extractor/
├── link_extractor.py        # Main script
├── requirements.txt         # Project dependencies
├── setup.py                 # Package setup file
├── README.md                # Project documentation
├── LICENSE                  # License file
├── exceptions.txt           # List of domain exceptions
├── explored_domains.txt     # List of explored domains
├── extractors/              # Domain extractors
│   ├── __init__.py
│   ├── js_extractor.py      # JavaScript extractor
│   └── php_extractor.py     # PHP extractor
└── utils/                   # Utility modules
    ├── __init__.py
    ├── console.py           # Console output helpers
    └── database.py          # Database operations
```

## Warning

Running selenium can be a little bit taxing on your system depending on the hardware you run it on.
## License

This project is licensed under the MIT License - see the [LICENSE file](license.md) for details.
