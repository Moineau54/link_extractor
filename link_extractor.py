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
from selenium.common.exceptions import UnexpectedAlertPresentException, TimeoutException, WebDriverException
# import undetected_chromedriver as uc
from undetected_geckodriver import Firefox as U_Firefox

from bs4 import BeautifulSoup
import subprocess
import sys
import os
import shutil
import time
import requests
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


import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()

class LinkExtractor:
    """Main class for extracting links and domains from web pages."""
    
    def __init__(self, url, verbose=False, with_head=False, screenshot=False, screenshot_dir=False, time=40):
        """
        Initialize the LinkExtractor.
        
        Args:
            url (str): The URL to analyze
            verbose (bool): Whether to display verbose output
        """
        self.url = url
        self.time = time
        self.with_head = with_head
        self.domain = ""
        self.screenshot = screenshot
        self.screenshot_dir = screenshot_dir
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
        # reverse the order of the list
        self.explored_domains.reverse()

        for domain_entry in self.explored_domains:
            if not domain_entry:
                continue
                
            parts = domain_entry.split(" ")
            if len(parts) < 2:
                continue
                
            domain_url, domain_date = parts[0], parts[1]
            
            
            if domain_url.__contains__(self.url):
                # If the URL is found in the explored_domains list, check if it's the same date
                if domain_date == current_date:
                    self.logger.debug(f"{self.url} has already been explored today. Exiting...")
                    print(f"{self.url} has already been explored today. Exiting...")
                    return False
                else:
                    # Re-explore if the date is different
                    self.logger.debug(f"{self.url} has not been explored today. Re-exploring...")
                    print(f"{self.url} has not been explored today. Re-exploring...")
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
            
            if url.__contains__("connect.facebook.net"):
                print(url)
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # # Remove 'www.' prefix if present
            # if domain.startswith('www.'):
            #     domain = domain[4:]
                
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
                    
                # if domain.startswith('www.'):
                #     domain = domain[4:]
                    
                if ':' in domain:
                    domain = domain.split(':')[0]
                    
                return domain
            except:
                # If all else fails, return the original URL
                return url
    
    def fetch_with_retry(self, max_retries=3, backoff_factor=1.5):
        import requests
        """
        Attempt to fetch the webpage with retries.
        
        Args:
            max_retries (int): Maximum number of retry attempts
            backoff_factor (float): Multiplier for exponential backoff between retries
            
        Returns:
            BeautifulSoup: The parsed HTML content or None if all retries fail
        """
        import time
        
        retry_count = 0
        last_error = None
        
        # Save original URL
        original_url = self.url
        
        # Try different URL variations
        url_variations = [
            original_url,  # First try the original URL
            original_url.replace('https://', 'http://'),  # Try HTTP if HTTPS fails
        ]
        
        # Add www. prefix if it's not already there
        if '://' in original_url and '://www.' not in original_url:
            domain_part = original_url.split('://', 1)[1]
            url_with_www = original_url.split('://', 1)[0] + '://www.' + domain_part
            url_variations.append(url_with_www)
        
        # Try all URL variations with retries
        for url_variation in url_variations:
            self.url = url_variation
            if not self.url.startswith('https://') and not self.url.startswith('http://'):
                self.url = f"https://{self.url}"
            
            # Extract the domain correctly for ping
            self.domain = self._extract_domain_from_url(self.url, self.url)
            
            # Validate domain before pinging
            if not self.domain:
                self.logger.debug("Empty domain detected, skipping ping test")
                continue
                
            for attempt in range(max_retries):
                try:
                    # Update this to handle empty domain string
                    if self.domain:  # Only ping if we have a domain
                        try:
                            output = subprocess.run(["ping", "-c", "1", self.domain], 
                                    capture_output=True, text=True, check=True)
                            # Continue only if ping was successful
                            if output.stdout.__contains__("0% packet loss"):
                                retry_count += 1
                                
                                self.logger.debug(f"Attempt {retry_count} with URL: {self.url}")
                                print(f"Attempt {retry_count} with URL: {self.url}")
                                
                                # Attempt to fetch the webpage
                                result = self._fetch_webpage()
                                
                                if result is not None:
                                    # Success - return the result
                                    self.logger.debug(f"Successfully fetched the webpage after {retry_count} attempts")
                                    print(f"Successfully fetched the webpage after {retry_count} attempts")
                                    return result
                        except Exception as sel_error:
                            # Ping failed, try requests anyway
                            self.logger.debug(f"Selenium debug: {sel_error}")
                            
                    
                            # If ping failed or domain was empty, try with requests directly
                            try:
                                # Add SSL verification disable for sites with bad certificates
                                if not self.url.startswith('https://') and not self.url.startswith('http://'):
                                    response = requests.get(f"https://{self.url}", verify=False)
                                else:
                                    response = requests.get(self.url, verify=False)

                                if response.status_code == 200:
                                    retry_count += 1
                                    
                                    self.logger.debug(f"Attempt {retry_count} with direct request to: {self.url}")
                                    print(f"Attempt {retry_count} with direct request to: {self.url}")
                                    
                                    # Parse the content directly
                                    return BeautifulSoup(response.text, "lxml")
                            except Exception as req_error:
                                self.logger.debug(f"Request debug: {req_error}")
                    
                    # Only do exponential backoff if we're not on the last attempt or last URL variation
                    if attempt < max_retries - 1 or url_variation != url_variations[-1]:
                        wait_time = backoff_factor ** attempt
                        self.logger.debug(f"Retrying in {wait_time:.1f} seconds...")
                        print(f"Retrying in {wait_time:.1f} seconds...")
                        time.sleep(wait_time)
                        
                except Exception as e:
                    self.logger.debug(f"debug during attempt: {e}")
        
        # All retries failed, restore original URL and return None
        self.url = original_url
        self.logger.debug(f"Failed to fetch the webpage after {retry_count} attempts")
        print(f"Failed to fetch the webpage after {retry_count} attempts")
        return None


    
        """
        Fetch the webpage content with improved error handling.
        
        Returns:
            BeautifulSoup: The parsed HTML content or None on error
        """
        import requests

        # Try requests first as a simpler, more reliable method
        try:
            self.logger.debug(f"Attempting to fetch URL with requests: {self.url}")
            print(f"Attempting to fetch URL with requests: {self.url}")
            
            # Set up headers to mimic a browser
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
            }
            
            if not self.url.startswith('https://') and not self.url.startswith('http://'):

                response = requests.get(f"https://{self.url}", headers=headers, verify=False, timeout=30)
            else:
                response = requests.get(self.url, headers=headers, verify=False, timeout=30)
            
            if response.status_code == 200:
                self.logger.debug("Successfully fetched webpage with requests")
                print("Successfully fetched webpage with requests")
                return BeautifulSoup(response.text, "lxml")
        except Exception as req_error:
            self.logger.warning(f"Initial request attempt failed: {req_error}")
            # Continue to Selenium approach if requests fails
        
        # If requests fails or returns non-200, try with Selenium
        print("Falling back to Selenium...")
        options = Options()
        if not self.with_head:
            options.add_argument("--headless")
        
        options.add_argument("--ignore-certificate-errors")
        options.add_argument("--ignore-ssl-errors")
        options.set_preference("security.tls.version.min", 1)
        
        driver = None
        try:
            self.logger.debug(f"Initializing Firefox driver for: {self.url}")
            print(f"Initializing Firefox driver for: {self.url}")
            
            # Use direct Firefox driver initialization
            from selenium.webdriver import Firefox
            
            # Keep it simple - avoid undetected_geckodriver which seems to cause issues
            driver = Firefox(options=options)
            driver.set_page_load_timeout(self.time)
            
            self.logger.debug(f"Navigating to URL: {self.url}")
            print(f"Navigating to URL: {self.url}")
            driver.get(self.url)
            element_present = EC.presence_of_element_located((By.TAG_NAME, "title"))
            WebDriverWait(driver, self.time).until(element_present)
            # Wait briefly for page to load
            import time
            time.sleep(5)
            
            # Get page content
            content = driver.page_source
            
            # Close driver
            if driver:
                try:
                    driver.quit()  # Use quit() instead of close() to ensure full cleanup
                except Exception as close_error:
                    self.logger.warning(f"debug closing driver: {close_error}")
            
            # Parse and return the content
            return BeautifulSoup(content, "lxml")
            
        except Exception as selenium_error:
            self.logger.debug(f"Selenium approach failed: {selenium_error}")
            
            # Make sure driver is closed
            if driver:
                try:
                    driver.quit()
                except:
                    pass
            
            # Final fallback - try requests again with different settings
            try:
                self.logger.debug("Final attempt with requests")
                print("Final attempt with requests")
                if not self.url.startswith('https://') and not self.url.startswith('http://'):
                    response = requests.get(
                        f"https://{self.url}", 
                        verify=False, 
                        timeout=30,
                        headers={'User-Agent': 'Mozilla/5.0'},
                        allow_redirects=True
                    )
                else:
                    response = requests.get(
                        self.url, 
                        verify=False, 
                        timeout=30,
                        headers={'User-Agent': 'Mozilla/5.0'},
                        allow_redirects=True
                    )
                
                if response.status_code == 200:
                    return BeautifulSoup(response.text, "lxml")
            except Exception as final_error:
                self.logger.debug(f"All fetch attempts failed: {final_error}")
            
            return Non
    
    def _fetch_webpage(self):
        """
        Fetch the webpage content with improved debug handling.
        First tries undetected_geckodriver, then falls back to requests if that fails.
        
        Returns:
            BeautifulSoup: The parsed HTML content or None on debug
        """
        import requests
        import time
        import os

        # Try undetected_geckodriver first
        print("Attempting to fetch with undetected_geckodriver...")
        options = Options()
        if not self.with_head:
            options.add_argument("--headless")
        
        options.add_argument("--ignore-certificate-errors")
        options.add_argument("--ignore-ssl-errors")
        options.set_preference("security.tls.version.min", 1)
        
        driver = None
        try:
            self.logger.debug(f"Initializing undetected Firefox driver for: {self.url}")
            print(f"Initializing undetected Firefox driver for: {self.url}")
            
            # Create a separate function to initialize the driver to isolate any problems
            def create_driver():
                return U_Firefox(options=options)
            
            # Initialize the driver
            driver = create_driver()
            
            if driver is None:
                raise Exception("Driver initialization returned None")
                
            driver.set_page_load_timeout(self.time)
            
            self.logger.debug(f"Navigating to URL: {self.url}")
            print(f"Navigating to URL: {self.url}")
            driver.set_page_load_timeout(self.time)
            driver.get(self.url)
            element_present = EC.presence_of_element_located((By.TAG_NAME, "title"))
            WebDriverWait(driver, self.time).until(element_present)
            # Wait briefly for page to load
            # time.sleep(5)
            
            if self.screenshot == True:
                # Get page content
                domain = self._extract_domain_from_url(self.url, self.url)
                timestamp = time.strftime("%Y%m%d-%H%M%S")
                filename = f"{domain}_{timestamp}.png"
                filepath = os.path.join(self.screenshot_dir, filename)
                
                # Take the screenshot
                print(f"Taking screenshot of {self.url}")
                if not os.path.exists(self.screenshot_dir):
                    os.makedirs(self.screenshot_dir)
                
                # Save the screenshot
                # time.sleep(20) # waits twenty seconds for the page to load completely
                driver.save_screenshot(filepath)
                print(f"Screenshot saved to {filepath}")
            content = driver.page_source
            
            # Close driver
            try:
                driver.quit()  # Use quit() instead of close() to ensure full cleanup
            except Exception as close_error:
                self.logger.warning(f"debug closing driver: {close_error}")
            
            # Parse and return the content
            return BeautifulSoup(content, "lxml")
            
        except Exception as selenium_error:
            self.logger.debug(f"undetected_geckodriver approach failed: {selenium_error}")
            
            # Make sure driver is closed
            if driver:
                try:
                    driver.quit()
                except Exception:
                    pass
            
            # Fall back to requests
            try:
                self.logger.debug(f"Falling back to requests for URL: {self.url}")
                print(f"Falling back to requests for URL: {self.url}")
                
                # Set up headers to mimic a browser
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                
                if not self.url.startswith('https://') and not self.url.startswith('http://'):
                    response = requests.get(
                        f"https://{self.url}", 
                        headers=headers,
                        verify=False, 
                        timeout=30,
                        allow_redirects=True
                    )
                else:
                    response = requests.get(
                        self.url, 
                        headers=headers,
                        verify=False, 
                        timeout=30,
                        allow_redirects=True
                    )
                    
                if response.status_code == 200:
                    self.logger.debug("Successfully fetched webpage with requests")
                    print("Successfully fetched webpage with requests")
                    return BeautifulSoup(response.text, "lxml")
                else:
                    self.logger.debug(f"Request failed with status code: {response.status_code}")
                    print(f"Request failed with status code: {response.status_code}")
            except Exception as req_error:
                self.logger.debug(f"Requests approach also failed: {req_error}")
            
            return None
    
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
                        domain = self._extract_domain_from_url(source, self.url)
                        if domain not in self.exceptions and domain not in self.domains and domain != self.domain:
                            self.domains.append(domain)

                elif ".php" in source:
                    # Add to php_links, handled by another method
                    pass
                else:
                    domain = self._extract_domain_from_url(source, self.url)
                    if domain not in self.exceptions and domain != self.current_site_domain:
                        if domain not in self.domains and domain not in self.exceptions and domain != self.domain:
                            self.domains.append(domain)
            else:
                
                code_type = script.get("type")
                code = script.text
                if code_type:
                    self.logger.debug("Extracting domains from the JavaScript code")
                    list_of_domains = self.js_extractor.extract_embedded_domains(code, self.url, self.exceptions, self.verbose)

                    for domain in list_of_domains:
                        # Extract just the domain part
                        clean_domain = self._extract_domain_from_url(domain, self.url)
                        if clean_domain not in self.exceptions and clean_domain != self.current_site_domain and clean_domain not in self.domains and clean_domain not in self.js_domains:
                            self.js_domains.append(clean_domain)

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
                    if domain not in self.exceptions and domain != self.current_site_domain and domain not in self.domains and domain not in self.exceptions and domain != self.domain:
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
            if domain not in self.domains and domain not in self.exceptions and domain != self.domain:
                self.domains.append(domain)
    
    def _extract_iframe_domains(self, soup):
        """Searches for domains in the iframe tag"""
        self.logger.debug("Checking for iframe tags")
        iframes = soup.find_all("iframe")
        iframe_domains = []
        if iframes:
            self.logger.debug("Checking for domains in iframe tags")

            for frame in iframes:
                source = frame.get("src")
                if source:
                    domain = self._extract_domain_from_url(source, self.url)
                    # Fix: Changed no_script_domains to iframe_domains
                    if domain not in self.exceptions and domain != self.current_site_domain and domain not in self.domains and domain not in iframe_domains:
                        iframe_domains.append(domain)
                        self.logger.debug(f"Found domain in iframe: {domain}")
            
            for domain in iframe_domains:
                if domain not in self.domains and domain not in self.exceptions and domain != self.domain:
                    self.domains.append(domain)

    def _extract_head_domains(self, soup):
        """Searches for domains in the head tag"""
        self.logger.debug("Checking for the head tag")
        head = soup.find("head")
        head_domains = []

        if head:
            self.logger.debug("Checking for domains in the head")
            head_str = str(head)
            if head_str.__contains__("connect.facebook.net"):
                print("test")
            domains = self.js_extractor.extract_embedded_domains([head_str], self.url, self.exceptions, self.verbose)
            for domain in domains:
                if domain not in self.domains and domain not in self.exceptions and domain != self.domain:
                    self.domains.append(domain)

    def _extract_script_domains_in_body(self, soup):
        """Searches for domains in the script tags in the body"""
        self.logger.debug("Checking for the body tag")
        body = soup.find("body")
        script_domains = []

        if body:
            self.logger.debug("Checking for script tags in the body")
            scripts = body.find_all("script")

            if scripts:
                self.logger.debug("Checking for domains in the scripts tags")

                for script in scripts:
                    source = script.get("src")
                    if source:
                        domain = self._extract_domain_from_url(source, self.url)
                        if domain not in self.exceptions and domain != self.current_site_domain and domain not in self.domains and domain not in script_domains:
                            script_domains.append(domain)
                            self.logger.debug(f"Found domain in script: {domain}")
            
            for domain in script_domains:
                if domain not in self.domains and domain not in self.exceptions and domain != self.domain:
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
            if domain not in self.domains and self._is_valid_domain(domain) and domain != self.domain:
                self.domains.append(domain)
                
        for domain in self.php_domains:
            if domain not in self.domains and self._is_valid_domain(domain) and domain != self.domain:
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
        
    def process_domains_from_file(self, filename, verbose, with_head):
        """
        Read domains from a file and process each one.
        
        Args:
            filename (str): Path to the file containing domains (one per line)
            verbose (boolean)
            with_head (boolean): checks if it opens a webbrowser window
            
        Returns:
            list: List of results for each domain
        """
        import requests

        results = []
        
        try:
            with open(filename, 'r') as f:
                domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                
            self.logger.debug(f"Read {len(domains)} domains from {filename}")
            
            i = 0
            lenght = len(domains)
            for i in range(lenght):
                # Add http:// prefix if not present
                domain = domains[i]

                self.url = domain

                
                domain = self._get_domain(domain)
                

                try:
                    output = subprocess.run(["ping", "-c", "1", domain], 
                            capture_output=True, text=True, check=True)

                    if output.stdout.__contains__("0% packet loss"):
                        
                        if domain != '':
                            if not domain.startswith('https://'):
                                domain = 'https://' + domain
                            
                            self.logger.debug(f"Processing domain: {domain}")
                            
                            
                            # Create a new extractor instance for this domain
                            
                            self.run()
                            
                            # Get results
                            result = {
                                'domain': domain,
                                'total_domains': len(self.domains),
                                'js_domains': len(self.js_domains),
                                'php_domains': len(self.php_domains),
                                'domains_list': self.domains
                            }
                            
                            results.append(result)
                            self.logger.debug(f"Completed processing {domain}")
                            print(f"Completed processing {domain}")
                            # time.sleep(1)
                    else:
                        print(f"{domain} is unreachable")
                except Exception as e:
                    self.logger.debug(e)
                    try:
                        if domain.__contains__("https://"):
                            response = requests.get(domain, verify=False)
                        else:
                            response = requests.get(f"https://{domain}", verify=False)
                        response.raise_for_status()
                        if response.status_code == 200:
                            if domain != '':
                                if not domain.startswith('https://'):
                                    domain = 'https://' + domain
                                
                                self.logger.debug(f"Processing domain: {domain}")
                                
                                
                                self.url = domain
                                self.run()
                                
                                # Get results
                                result = {
                                    'domain': domain,
                                    'total_domains': len(self.domains),
                                    'js_domains': len(self.js_domains),
                                    'php_domains': len(self.php_domains),
                                    'domains_list': self.domains
                                }
                                
                                results.append(result)
                                self.logger.debug(f"Completed processing {domain}")
                                print(f"Completed processing {domain}")
                                # time.sleep(1)
                    except Exception as e:
                        self.logger.debug(e)
                        print(f"{domain} is unreachable")
            
            return results
        except Exception as e:
            self.logger.debug(f"debug processing domains from file: {str(e)}")
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
            self.logger.debug("Could not connect to database")
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
            self.logger.debug(f"debug retrieving domains: {str(e)}")
        finally:
            conn.close()
    
    def _get_domain(self, url):
        _domain = url
        if _domain.__contains__("http://"):
            _domain = url.replace("http://", "")
        elif _domain.__contains__("https://"):
            _domain = url.replace("https://", "")
        
        if _domain.__contains__("www."):
            _domain = _domain.replace("www.", "")
        
        _domain = _domain.split("/")[0]
        self.domain = _domain
        return _domain
    

    def run(self):
        """Run the link extraction process with improved debug handling."""
        try:
            
            
            # Check if URL has already been explored
            if not self._check_if_already_explored():
                return
            
            # Fetch the webpage using the retry mechanism
            soup = self.fetch_with_retry(max_retries=3, backoff_factor=1.5)
            if not soup:
                self.logger.debug(f"Could not fetch {self.url} after multiple attempts")
                print(f"Could not fetch {self.url} after multiple attempts")
                # Mark as explored anyway to avoid repeated failures
                self._update_explored_domains()
                return
            
            # Extract and analyze JavaScript links
            js_links = self._extract_js_links(soup)
            self._analyze_js_links(js_links)
            
            # Extract and analyze PHP links
            php_links = self._extract_php_links(soup)
            self._analyze_php_links(php_links)
            
            # Extract domains from noscript tags
            self._extract_noscript_domains(soup)

            # Extract domains from ifram tags
            self._extract_iframe_domains(soup)

            # Extract domains in the head tag
            self._extract_head_domains(soup)
            
            # Extract domains stored in the script tags in the body
            self._extract_script_domains_in_body(soup)
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
                    print(f"Found domain: {domain}")
            
            self.logger.debug("All done!")
            print("All done!")
            
        except Exception as e:
            self.logger.debug(f"debug: {str(e)}")
            import traceback
            self.logger.debug(traceback.format_exc())
            print("Check the logs for more details.")


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
    parser.add_argument("--screenshot", "-s", action="store_true", help="Take screenshots of websites")
    parser.add_argument("--screenshot-dir", "-sd", dest="screenshot_dir", default="screenshots", help="Directory to save screenshots (default: screenshots/)")
    parser.add_argument("--time", "-t", default=40, help="Custom load time")

    args = parser.parse_args()
    
    # Default to example URL if no mode specified
    if not (args.url or args.file or args.list):
        args.url = "https://www.example.com/"
    
    if not (args.with_head):
        args.with_head = False
    # Handle conflicting sort options
    if args.asc and args.desc:
        parser.debug("Cannot specify both --asc and --desc")
        
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
        console.print(Padding(f"[bold red]→ Couldn't update from GitHub. debug: {e}[/bold red]", (0, 0, 0, 4)))



def main(args):
    import requests
    import os
    """Script entry point."""
    
    
    console_utils = ConsoleHelper(args.verbose)
    console_utils.display_banner(args.verbose)
    
    # Default to URL mode with example.com if no mode specified
    if args.url:
        # URL mode - analyze a single URL
        
        if args.url.startswith("http://") or args.url.startswith("https://"):
            url = args.url
        else:
            url = "https://" + args.url
        if args.url.endswith("/"):
            url = args.url[:-1]

        if args.screenshot_dir and args.screenshot:
            screenshot_dir = args.screenshot_dir
        else:
            screenshot_dir = f"{os.getcwd()}/screenshots"
        
        if args.time:
            time_variable = int(args.time)
        
        extractor = LinkExtractor(url=url, verbose=args.verbose, with_head=args.with_head, screenshot=args.screenshot, screenshot_dir=screenshot_dir, time=time_variable)
        
        
        domain = extractor._get_domain(url)
        
        try:
            output = subprocess.run(["ping", "-c", "1", domain], 
                            capture_output=True, text=True, check=True)
            
            if not url.startswith('https://'):
                url = 'https://' + url
            if output.stdout.__contains__("0% packet loss") == True:
                extractor.run()
            else:
                print(f"{url} is unreachable.")
        except Exception as e:
            if not url.startswith('https://') and not url.startswith('http://'):
                url = 'https://' + url
            
            try:
                response = requests.get(url, verify=False)
                response.raise_for_status()
                if response.status_code != 200:
                    print(e)
                    return
                
                if not url.startswith('https://'):
                    url = 'https://' + url

                if response.status_code == 200:
                    extractor.run()
                else:
                    print(f"{url} is unreachable.")
            except Exception as e:
                print(e)
                print(f"{url} is unreachable.")
        
        
        
        
        
        sys.exit()
    elif args.file:
        # File mode - process multiple domains from a file
        if args.screenshot_dir and args.screenshot:
            screenshot_dir = args.screenshot_dir
        elif args.screenshot:
            screenshot_dir = f"{os.getcwd()}/screenshots"

        if args.time:
            time_variable = int(args.time)
        
        extractor = LinkExtractor("", args.verbose, args.with_head, screenshot=args.screenshot, screenshot_dir=args.screenshot_dir, time=time_variable)  # Empty URL as it will be overridden
        results = extractor.process_domains_from_file(args.file, args.verbose, args.with_head)
        print(f"\nProcessed {len(results)} domains from {args.file}")
        sys.exit()
    elif args.list:
        # List mode - show domains from database
        extractor = LinkExtractor("", args.verbose, args.with_head, screenshot=args.screenshot, screenshot_dir=args.screenshot_dir)  # Empty URL as we're just querying
        
        # Create database connection
        conn = extractor.db.create_connection("domains.db")
        if not conn:
            extractor.logger.debug("Could not connect to database")
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
    args = parse_arguments()
    get_update()
    main(args)
