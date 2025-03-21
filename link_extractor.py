#!.venv/bin/python
"""
Link Extractor - A tool for extracting domains from websites

This script scrapes a specified webpage, extracts script tags and PHP files,
analyzes JavaScript and PHP files, and identifies domains referenced within them.
It helps security researchers and web developers identify external 
dependencies and potential security risks in websites.

Usage:
    python link_extractor.py [URL] [-v|--verbose] [-h|--help]

Arguments:
    URL          - The target website URL (defaults to https://www.example.com/)
    -v, --verbose - Display detailed output including all scripts found
    -h, --help    - Display usage information
"""

# Selenium
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.firefox.options import Options
# import undetected_chromedriver as uc
from undetected_geckodriver import Firefox as U_Firefox

from bs4 import BeautifulSoup
import subprocess
import sys
import os
import shutil
import time
import re
from urllib.parse import urlparse
import argparse
import logging

# Import local modules
from extractors.js_extractor import JsExtractor
from extractors.php_extractor import PhpExtractor
from utils.database import Database
from utils.console import ConsoleHelper

# rich console
from rich.console import Console
from rich.padding import Padding

console = Console()

class LinkExtractor:
    """Main class for extracting links and domains from web pages."""
    
    def __init__(self, url, verbose=False, with_head=False):
        """
        Initialize the LinkExtractor.
        
        Args:
            url (str): The URL to analyze
            verbose (bool): Whether to display verbose output
        """
        self.url = url
        self.with_head = with_head
        self.verbose = verbose
        self.logger = self._setup_logger()
        self.console = ConsoleHelper(verbose)
        self.domains = []
        self.js_domains = []
        self.php_domains = []
        self.current_site_domain = self._extract_domain_from_url(url, url)
        self.explored_domains = []
        self.exceptions = []
        
        # Initialize extractors
        self.js_extractor = JsExtractor()
        self.php_extractor = PhpExtractor()
        self.db = Database(verbose)
        
        # Load configuration
        self._load_configuration()
    
    def _setup_logger(self):
        """Set up the logger with appropriate configuration."""
        logger = logging.getLogger('link_extractor')
        logger.setLevel(logging.DEBUG if self.verbose else logging.INFO)
        
        # Create console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG if self.verbose else logging.INFO)
        
        # Create formatter
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        ch.setFormatter(formatter)
        
        # Add handler to logger
        logger.addHandler(ch)
        
        return logger
    
    def _load_configuration(self):
        """Load configuration files (explored domains and exceptions)."""
        self._load_explored_domains()
        self._load_exceptions()
    
    def _load_explored_domains(self):
        """Load the list of already explored domains."""
        if not os.path.exists("explored_url.txt"):
            with open("explored_url.txt", "w") as f:
                f.write(f"https://www.example.com/ {time.strftime('%d.%m.%Y')}\n")
            self.logger.debug("Created new explored_url.txt file")
            print("Created new explored_url.txt file")
        
        with open("explored_url.txt", "r") as f:
            self.explored_domains = [line.strip() for line in f.readlines() if line.strip()]
            self.logger.debug(f"Loaded {len(self.explored_domains)} explored domains")
    
    def _load_exceptions(self):
        """Load the list of domain exceptions."""
        if not os.path.exists("exceptions.txt"):
            with open("exceptions.txt", "w") as f:
                f.write("example.com\n")
            self.logger.debug("Created new exceptions.txt file")
            print("Created new exceptions.txt file")
        
        with open("exceptions.txt", "r") as f:
            self.exceptions = [line.strip() for line in f.readlines() if line.strip()]
            self.logger.debug(f"Loaded {len(self.exceptions)} exceptions")
    
    def _check_if_already_explored(self):
        """
        Check if the current URL has already been explored recently.
        
        Returns:
            bool: True if the URL should be explored, False otherwise
        """
        current_date = time.strftime('%d.%m.%Y')
        
        for domain_entry in self.explored_domains:
            if not domain_entry:
                continue
                
            parts = domain_entry.split(" ")
            if len(parts) < 2:
                continue
                
            domain_url, domain_date = parts[0], parts[1]
            
            if domain_url == self.url:
                if domain_date == current_date:
                    self.logger.debug(f"{self.url} has already been explored today. Exiting...")
                    print(f"{self.url} has already been explored today. Exiting...")
                    return False
                else:
                    # Try to calculate days difference
                    try:
                        # Convert string dates to integers for comparison
                        domain_day, domain_month, domain_year = map(int, domain_date.split('.'))
                        current_day, current_month, current_year = map(int, current_date.split('.'))
                        
                        # Simple check - if it's more than a month ago, re-explore
                        if (domain_year < current_year or 
                            (domain_year == current_year and domain_month < current_month - 1) or
                            (domain_year == current_year and domain_month == current_month - 1 and domain_day < current_day)):
                            self.logger.debug(f"{self.url} has not been explored in the last 30 days. Re-exploring...")
                            print(f"{self.url} has not been explored in the last 30 days. Re-exploring...")
                            return True
                        else:
                            self.logger.debug(f"{self.url} has been explored within the last 30 days. Exiting...")
                            print(f"{self.url} has been explored within the last 30 days. Exiting...")
                            return False
                    except ValueError:
                        # If date parsing fails, re-explore to be safe
                        self.logger.debug("Couldn't determine exploration age. Re-exploring...")
                        print("Couldn't determine exploration age. Re-exploring...")
                        return True
        
        # If URL not found in explored_domains, explore it
        return True
    
    def _extract_domain_from_url(self, url, base_url):
        """
        Extract only the domain part from a URL.
        
        Args:
            url (str): A full URL
            base_url (str): The base URL for relative paths
            
        Returns:
            str: The extracted domain name
        """
        try:
            # If URL doesn't start with http/https, add it to enable parsing
            domain_suffix_pattern = r'\.[a-zA-Z]{2,}'
            has_domain_suffix = re.search(domain_suffix_pattern, url)
            if not has_domain_suffix:
                if not url.startswith('http'):
                    if url.startswith('//'):
                        url = 'https:' + url
                    else:
                        url = base_url.rstrip('/') + '/' + url.lstrip('/')
                
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # Remove 'www.' prefix if present
            if domain.startswith('www.'):
                domain = domain[4:]
                
            # Handle cases where the domain might contain port information
            if ':' in domain:
                domain = domain.split(':')[0]
                
            return domain
        except Exception as e:
            # In case of parsing errors, do a simple extraction
            try:
                if '//' in url:
                    domain = url.split('//')[1].split('/')[0]
                else:
                    domain = url.split('/')[0]
                    
                if domain.startswith('www.'):
                    domain = domain[4:]
                    
                if ':' in domain:
                    domain = domain.split(':')[0]
                    
                return domain
            except:
                # If all else fails, return the original URL
                return url
    
    def _fetch_webpage(self):
        """
        Fetch the webpage content.
        
        Returns:
            BeautifulSoup: The parsed HTML content or None on error
        """
        print("running undetected geckodriver (selenium)")
        # driver = uc.Chrome(headless=False,use_subprocess=False)
        options = Options()
        if self.with_head == False:
            options.add_argument("--headless")
        driver = U_Firefox(options=options)
        self.logger.debug(f"Fetching URL: {self.url}")
        print(f"Fetching URL: {self.url}")
        url = self.url
        driver.get(url)
        
        try:
            self.logger.debug("loading the page (20s)")
            print("loading the page (20s)")
            # driver.implicitly_wait(20)
            element = WebDriverWait(driver, 20)
        finally:
            if driver.title != None:
                try:
                    content = driver.page_source
                except EC.Alert as a:
                    print(a)
                    return None
                driver.close()
                return BeautifulSoup(content, "lxml")
            else:
                return None
            
        #     if response.status_code == 200:
        #         self.logger.info("URL fetched successfully!")
        #         return BeautifulSoup(response.text, "html.parser")
        #     else:
        #         self.logger.error(f"Failed to fetch the URL: {response.status_code}")
        #         return None
        # except requests.exceptions.RequestException as e:
        #     self.logger.error(f"Error fetching URL: {e}")
        #     return None
    
    def _extract_js_links(self, soup):
        """
        Extract JavaScript links from the HTML.
        
        Args:
            soup (BeautifulSoup): The parsed HTML
            
        Returns:
            list: List of JavaScript links
        """
        js_links = []
        
        # Extract from script tags
        scripts = soup.find_all("script")
        self.logger.debug(f"Found {len(scripts)} script tags in the webpage")
        
        for script in scripts:
            source = script.get("src")
            if source:
                if source.endswith(".js") or ".js?" in source:
                    self.logger.debug(f"Found JavaScript file: {source}")
                    if source.startswith("//"):
                        source = "https:" + source
                    
                    if source:
                        js_links.append(source)
                elif ".php" in source:
                    # Add to php_links, handled by another method
                    pass
                else:
                    domain = self._extract_domain_from_url(source, self.url)
                    if domain not in self.exceptions and domain != self.current_site_domain:
                        if domain not in self.domains:
                            self.domains.append(domain)
        
        # Extract from link tags
        link_tags = soup.find_all("link")
        self.logger.debug(f"Found {len(link_tags)} link tags in the webpage")
        
        for link_tag in link_tags:
            href = link_tag.get("href")
            if href:
                self.logger.debug(f"Found link tag: {href}")
                
                if href.endswith(".js") or ".js?" in href:
                    self.logger.debug(f"Found JavaScript file: {href}")
                    if href.startswith("//"):
                        href = "https:" + href
                    
                    if href:
                        js_links.append(href)
                else:
                    domain = self._extract_domain_from_url(href, self.url)
                    if domain not in self.exceptions and domain != self.current_site_domain and domain not in self.domains:
                        self.domains.append(domain)
        
        # Remove duplicates
        js_links = list(set(js_links))
        self.logger.debug(f"Found {len(js_links)} JavaScript files in the webpage")
        if js_links:
            print(f"Found {len(js_links)} JavaScript files in the webpage")
        
        return js_links
    
    def _analyze_js_links(self, js_links):
        """
        Analyze JavaScript links and extract domains.
        
        Args:
            js_links (list): List of JavaScript links to analyze
        """
        for js_link in js_links:
            self.logger.debug(f"Analyzing JavaScript file: {js_link}")
            
            
            # Extract domain from the js_link itself
            js_link_domain = self._extract_domain_from_url(js_link, self.url)
            if js_link_domain not in self.exceptions and js_link_domain != self.current_site_domain and js_link_domain not in self.domains and js_link_domain not in self.js_domains:
                self.js_domains.append(js_link_domain)
                self.logger.debug(f"Found domain from JS link: {js_link_domain}")
            
            # Download and analyze JS code
            if js_link.startswith("http") or js_link.startswith("//"):
                code = self.js_extractor.download_js_code(js_link, "", self.verbose)
            else:
                code = self.js_extractor.download_js_code(js_link, self.url, self.verbose)
            
            if code is not None:
                self.logger.debug("Extracting domains from the JavaScript code")
                list_of_domains = self.js_extractor.extract_embedded_domains(code, self.url, self.exceptions, self.verbose)
                
                for domain in list_of_domains:
                    # Extract just the domain part
                    clean_domain = self._extract_domain_from_url(domain, self.url)
                    if clean_domain not in self.exceptions and clean_domain != self.current_site_domain and clean_domain not in self.domains and clean_domain not in self.js_domains:
                        self.js_domains.append(clean_domain)
    
    def _extract_php_links(self, soup):
        """
        Extract PHP links from the HTML.
        
        Args:
            soup (BeautifulSoup): The parsed HTML
            
        Returns:
            list: List of PHP links
        """
        php_links = []
        
        # Extract from script tags
        scripts = soup.find_all("script")
        for script in scripts:
            source = script.get("src")
            if source and (".php" in source):
                self.logger.debug(f"Found PHP file: {source}")
                if source:
                    php_links.append(source)
        
        # Look for links to PHP files in anchor tags
        anchors = soup.find_all("a")
        for anchor in anchors:
            href = anchor.get("href")
            if href and (href.endswith(".php") or ".php?" in href):
                self.logger.debug(f"Found PHP file link: {href}")
                php_links.append(href)
        
        # Look for links to PHP files in form actions
        forms = soup.find_all("form")
        for form in forms:
            action = form.get("action")
            if action and (action.endswith(".php") or ".php?" in action):
                self.logger.debug(f"Found PHP file in form action: {action}")
                php_links.append(action)
        
        # Look for PHP includes in the current page (if it's a PHP page)
        if self.url.endswith(".php") or ".php?" in self.url:
            php_links.append(self.url)
        
        # Remove duplicates
        php_links = list(set(php_links))
        self.logger.debug(f"Found {len(php_links)} PHP files in the webpage")
        print(f"Found {len(php_links)} PHP files in the webpage")
        
        return php_links
    
    def _analyze_php_links(self, php_links):
        """
        Analyze PHP links and extract domains.
        
        Args:
            php_links (list): List of PHP links to analyze
        """
        if not php_links:
            return
            
        for php_link in php_links:
            self.logger.debug(f"Analyzing PHP file: {php_link}")
            
            
            # Extract domain from the PHP link itself
            php_link_domain = self._extract_domain_from_url(php_link, self.url)
            if php_link_domain not in self.exceptions and php_link_domain != self.current_site_domain and php_link_domain not in self.domains and php_link_domain not in self.php_domains:
                self.php_domains.append(php_link_domain)
                self.logger.debug(f"Found domain from PHP link: {php_link_domain}")
            
            # Download and analyze PHP code
            if php_link.startswith("http") or php_link.startswith("//"):
                code = self.php_extractor.download_php_code(php_link, "", self.verbose)
            else:
                code = self.php_extractor.download_php_code(php_link, self.url, self.verbose)
            
            if code is not None:
                self.logger.debug("Extracting domains from the PHP code")
                
                # Extract domains from the PHP code
                php_found_domains = self.php_extractor.extract_embedded_domains(code, self.url, self.exceptions, self.verbose)
                for domain in php_found_domains:
                    # Extract just the domain part
                    clean_domain = self._extract_domain_from_url(domain, self.url)
                    if clean_domain not in self.exceptions and clean_domain != self.current_site_domain and clean_domain not in self.domains and clean_domain not in self.php_domains:
                        self.php_domains.append(clean_domain)
                
                # Extract PHP includes
                includes = self.php_extractor.extract_php_includes(code, self.verbose)
                if includes and self.verbose:
                    self.logger.debug(f"Found {len(includes)} PHP includes")
                    for include in includes:
                        self.logger.debug(f" - {include}")
                        # Try to analyze included PHP files if they're accessible
                        if not include.startswith('/') and not include.startswith('http'):
                            # Relative path
                            base_path = os.path.dirname(php_link)
                            include_path = f"{base_path}/{include}"
                            self.logger.debug(f"Trying to analyze included PHP file: {include_path}")
                            try:
                                include_code = self.php_extractor.download_php_code(include_path, self.url, self.verbose)
                                if include_code:
                                    include_domains = self.php_extractor.extract_embedded_domains(include_code, self.url, self.exceptions, self.verbose)
                                    for domain in include_domains:
                                        clean_domain = self._extract_domain_from_url(domain, self.url)
                                        if clean_domain not in self.exceptions and clean_domain != self.current_site_domain and clean_domain not in self.domains and clean_domain not in self.php_domains:
                                            self.php_domains.append(clean_domain)
                            except Exception as e:
                                self.logger.debug(f"Could not analyze included PHP file: {e}")
    
    def _extract_noscript_domains(self, soup):
        """
        Extract domains from noscript tags.
        
        Args:
            soup (BeautifulSoup): The parsed HTML
        """
        self.logger.debug("Checking for noscript tags")
        
        noscript = soup.find_all("noscript")
        no_script_domains = []
        
        if noscript:
            self.logger.debug("Checking for domains in noscript tags")
            
            
            
            for ns in noscript:
                # Find iframes within noscript tags
                iframes = ns.find_all("iframe")
                for iframe in iframes:
                    source = iframe.get("src")
                    if source:
                        domain = self._extract_domain_from_url(source, self.url)
                        if domain not in self.exceptions and domain != self.current_site_domain and domain not in self.domains and domain not in no_script_domains:
                            no_script_domains.append(domain)
                            self.logger.debug(f"Found domain in noscript iframe: {domain}")
                
                # Also check for img tags in noscript
                images = ns.find_all("img")
                for img in images:
                    source = img.get("src")
                    if source:
                        domain = self._extract_domain_from_url(source, self.url)
                        if domain not in self.exceptions and domain != self.current_site_domain and domain not in self.domains and domain not in no_script_domains:
                            no_script_domains.append(domain)
                            self.logger.debug(f"Found domain in noscript img: {domain}")
        
        self.logger.debug(f"Found {len(no_script_domains)} domains in the noscript tags")
        print(f"Found {len(no_script_domains)} domains in the noscript tags")
        
        for domain in no_script_domains:
            if domain not in self.domains:
                self.domains.append(domain)
    
    def _save_domains_to_database(self):
        """Save the extracted domains to the database."""
        self.logger.debug("Saving the domains to the database")
        print("Saving the domains to the database")

        conn = self.db.create_connection("domains.db")
        self.db.create_table(conn)
        
        # Clean up any empty domain entries in the database
        c = conn.cursor()
        c.execute("DELETE FROM domains WHERE domain = '' OR domain IS NULL")
        if c.rowcount > 0:
            self.logger.debug(f"Cleaned up {c.rowcount} empty domain entries from database")
            
        conn.commit()
        
        self.logger.debug("Saving the changes to database")
        
        
        conn = self.db.create_connection("domains.db")
        self.db.create_table(conn)
        
        # Consolidate all domains and filter out invalid ones
        valid_domains = []
        for domain in self.js_domains:
            if domain not in self.domains and self._is_valid_domain(domain):
                self.domains.append(domain)
                
        for domain in self.php_domains:
            if domain not in self.domains and self._is_valid_domain(domain):
                self.domains.append(domain)
        
        # Filter the final domains list
        valid_domains = [domain for domain in self.domains if self._is_valid_domain(domain)]
        
        # Insert domains into database
        for domain in valid_domains:
            self.db.insert_entry(conn, domain, 1, True, self.url, self.verbose)
        
        # Update exceptions in database (only valid ones)
        valid_exceptions = [exception for exception in self.exceptions if self._is_valid_domain(exception)]
        for exception in valid_exceptions:
            self.db.insert_entry(conn, exception, 0, False, self.url, self.verbose)
        
        conn.close()
    
    def _update_explored_domains(self):
        """Update the list of explored domains."""
        with open("explored_url.txt", "a") as f:
            f.write(f"{self.url} {time.strftime('%d.%m.%Y')}\n")
        self.logger.debug(f"Added {self.url} to explored domains")
        
    def process_domains_from_file(self, filename):
        """
        Read domains from a file and process each one.
        
        Args:
            filename (str): Path to the file containing domains (one per line)
            
        Returns:
            list: List of results for each domain
        """
        results = []
        
        try:
            with open(filename, 'r') as f:
                domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                
            self.logger.debug(f"Read {len(domains)} domains from {filename}")
            
            
            for domain in domains:
                # Add http:// prefix if not present
                if not domain.startswith('https://'):
                    domain = 'https://' + domain
                
                self.logger.debug(f"Processing domain: {domain}")
                
                
                # Create a new extractor instance for this domain
                extractor = LinkExtractor(domain, self.verbose, self.with_head)
                extractor.run()
                
                # Get results
                result = {
                    'domain': domain,
                    'total_domains': len(extractor.domains),
                    'js_domains': len(extractor.js_domains),
                    'php_domains': len(extractor.php_domains),
                    'domains_list': extractor.domains
                }
                
                results.append(result)
                self.logger.debug(f"Completed processing {domain}")
                print(f"Completed processing {domain}")
            
            return results
        except Exception as e:
            self.logger.error(f"Error processing domains from file: {str(e)}")
            return []
            
    
    def _is_valid_domain(self, domain):
        """
        Check if a domain string is valid and non-empty.
        
        Args:
            domain (str): The domain to check
        
        Returns:
            bool: True if the domain is valid, False otherwise
        """
        if not domain or len(domain.strip()) == 0:
            return False
        
        # Basic domain validation - must have at least one dot and valid characters
        if '.' not in domain:
            return False
            
        # Check for valid domain characters (letters, numbers, hyphen, dot)
        valid_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.')
        if not all(char in valid_chars for char in domain):
            return False
        
        return True

    
    def output_domains_by_occurrences(self, ascending=True):
        """
        Output domains sorted by their occurrences in the database.
        
        Args:
            ascending (bool): Whether to sort in ascending order (default: True)
        """
        conn = self.db.create_connection("domains.db")
        if not conn:
            self.logger.error("Could not connect to database")
            return
            
        try:
            c = conn.cursor()
            order = "ASC" if ascending else "DESC"
            c.execute(f"SELECT domain, occurrences, is_tracker, origin FROM domains ORDER BY occurrences {order}")
            rows = c.fetchall()
            
            if not rows:
                self.logger.debug("No domains found in the database")
                print("No domains found in the database")
                return
                
            # Print header
            self.logger.debug(f"{'Domain':<40} | {'Occurrences':<12} | {'Tracker':<8} | {'Origin':<30}")
            print(f"{'Domain':<40} | {'Occurrences':<12} | {'Tracker':<8} | {'Origin':<30}")
            self.logger.debug('-' * 95)
            print('-' * 95)
            
            # Print rows
            for row in rows:
                domain, occurrences, is_tracker, origin = row
                
                # Format origin to fit
                origin_str = str(origin or "")
                if len(origin_str) > 30:
                    origin_str = origin_str[:27] + "..."
                    
                self.logger.debug(f"{domain:<40} | {occurrences:<12} | {'Yes' if is_tracker else 'No':<8} | {origin_str:<30}")
                print(f"{domain:<40} | {occurrences:<12} | {'Yes' if is_tracker else 'No':<8} | {origin_str:<30}")
                
            self.logger.debug(f"\nTotal domains: {len(rows)}")
            print(f"\nTotal domains: {len(rows)}")
            
        except Exception as e:
            self.logger.error(f"Error retrieving domains: {str(e)}")
        finally:
            conn.close()
    
    def run(self):
        """Run the link extraction process."""
        try:
            self.console.display_banner(self.verbose)
            
            # Check if URL has already been explored
            if not self._check_if_already_explored():
                return
            
            # Fetch the webpage
            soup = self._fetch_webpage()
            if not soup:
                return
            
            # Extract and analyze JavaScript links
            js_links = self._extract_js_links(soup)
            self._analyze_js_links(js_links)
            
            # Extract and analyze PHP links
            php_links = self._extract_php_links(soup)
            self._analyze_php_links(php_links)
            
            # Extract domains from noscript tags
            self._extract_noscript_domains(soup)
            
            # Save domains to the database
            self._save_domains_to_database()
            
            # Update the list of explored domains
            self._update_explored_domains()
            
            # Display results
            if "" in self.domains:
                self.domains.remove("")
            
            self.logger.debug(f"Total unique domains found: {len(self.domains)}")
            print(f"Total unique domains found: {len(self.domains)}")
            for domain in self.domains:
                if domain != '':
                    self.logger.debug(f"Found domain: {domain}")
                    print(f"Found domain: {domain}")
            
            self.logger.debug("All done!")
            print("All done!")
            sys.exit()
        except Exception as e:
            self.logger.error(f"Error: {str(e)}")


def parse_arguments():
    """
    Parse command line arguments.
    
    Returns:
        argparse.Namespace: The parsed arguments
    """
    parser = argparse.ArgumentParser(description="Link Extractor - A tool for extracting domains from websites")
    
    # Create mutually exclusive group for main operation mode
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--url", dest="url", default=None, help="The target website URL to analyze")
    mode_group.add_argument("--file", "-f", dest="file", help="Process domains from a file (one domain per line)")
    mode_group.add_argument("--list", "-l", action="store_true", help="List all domains in the database")
    
    # Other arguments
    parser.add_argument("--with-head", "-wh", action="store_true", help="Runs the script with browser head (opens a browser window)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Display detailed output")
    parser.add_argument("--asc", action="store_true", help="Sort domains in ascending order (used with --list)")
    parser.add_argument("--desc", action="store_true", help="Sort domains in descending order (used with --list)")
    
    args = parser.parse_args()
    
    # Default to example URL if no mode specified
    if not (args.url or args.file or args.list):
        args.url = "https://www.example.com/"
    
    if not (args.with_head):
        args.with_head = False
    # Handle conflicting sort options
    if args.asc and args.desc:
        parser.error("Cannot specify both --asc and --desc")
        
    return args

def get_update():
    """Checks for updates from GitHub and asks for confirmation before applying."""
    repo_dir = os.path.dirname(os.path.abspath(__file__))
    python_executable = sys.executable
    script_path = os.path.abspath(__file__)

    try:
        # Return changes from remote without applying them yet
        subprocess.run(
            ["git", "-C", repo_dir, "fetch", "origin", "main"],
            capture_output=True, text=True
        )

        # Check if updates are available
        diff_result = subprocess.run(
            ["git", "-C", repo_dir, "diff", "HEAD..origin/main"],
            capture_output=True, text=True
        )

        if not diff_result.stdout:
            console.print("")
            console.print(Padding("[bold green]→ No updates found. Running the script normally...[/bold green]", (0, 0, 0, 4)))
            return

        # Show changes before updating
        console.print("")
        console.print(Padding("[bold yellow]→ Updates are available! Here are the changes:[/bold yellow]", (0, 0, 0, 4)))
        console.print(Padding(diff_result.stdout, (0, 0, 0, 4)))

        # Confirm first
        user_input = input("\n[?] Apply these updates? (y/n): ").strip().lower()
        if user_input != "y":
            console.print("")
            console.print(Padding("[bold cyan]→ Update skipped. Running the current version.[/bold cyan]", (0, 0, 0, 4)))
            return

        # Apply the update
        update_result = subprocess.run(
            ["git", "-C", repo_dir, "pull", "origin", "main"],
            capture_output=True, text=True
        )

        console.print("")
        console.print(Padding("[bold yellow]→ Update applied! Restarting script in 3 seconds...[/bold yellow]", (0, 0, 0, 4)))
        time.sleep(3)

        # Restart the script
        subprocess.Popen([python_executable, script_path] + sys.argv[1:])
        sys.exit(0)

    except Exception as e:
        console.print("")
        console.print(Padding(f"[bold red]→ Couldn't update from GitHub. Error: {e}[/bold red]", (0, 0, 0, 4)))


def main():
    """Script entry point."""
    args = parse_arguments()
    
    # Default to URL mode with example.com if no mode specified
    if args.url:
        # URL mode - analyze a single URL
        url = args.url
        if not url.startswith('https://'):
            url = 'https://' + url
        
        extractor = LinkExtractor(url, args.verbose, args.with_head)
        extractor.run()
    elif args.file:
        # File mode - process multiple domains from a file
        extractor = LinkExtractor("", args.verbose, args.with_head)  # Empty URL as it will be overridden
        results = extractor.process_domains_from_file(args.file)
        print(f"\nProcessed {len(results)} domains from {args.file}")
    elif args.list:
        # List mode - show domains from database
        extractor = LinkExtractor("", args.verbose, args.with_head)  # Empty URL as we're just querying
        
        # Create database connection
        conn = extractor.db.create_connection("domains.db")
        if not conn:
            extractor.logger.error("Could not connect to database")
            return
            
        # Set default sorting based on command line arguments
        ascending = args.asc
        descending = not args.asc  # Default to descending unless --asc specified
        
        # Call display_domains_table directly with appropriate parameters
        extractor.db.display_domains_table(
            conn,
            limit=None,
            min_occurrences=2,
            trackers_only=True,
            ascending=ascending,
            descending=descending
        )
        
        # Close the connection
        conn.close()


if __name__ == "__main__":
    get_update()
    main()
