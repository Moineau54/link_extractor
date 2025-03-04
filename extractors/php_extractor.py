#!/usr/bin/env python3
"""
PHP Extractor - A module for extracting domains from PHP files

This module analyzes PHP files, extracts embedded domains,
and identifies includes and requires within PHP code.
It helps security researchers and web developers identify PHP dependencies
and potential security risks in websites.
"""

import re
import requests
import logging


class PhpExtractor:
    """Class for extracting and analyzing PHP files from web pages."""
    
    def __init__(self):
        """Initialize the PHP extractor."""
        self.logger = logging.getLogger('link_extractor.php')
    
    def extract_embedded_domains(self, php_code, url, exceptions, verbose=False):
        """
        Extract domains from PHP code using regex.
        
        Args:
            php_code (list): List of PHP code strings to analyze
            url (str): Base URL for comparison
            exceptions (list): Domains to exclude
            verbose (bool): Whether to output verbose information
            
        Returns:
            list: List of extracted domains
        """
        domains = []
        pattern = r'https?:\/\/(?:www\.)?([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,})'
        
        # Get base domain for comparison
        try:
            base_domain_parts = url.split('.')[1] if len(url.split('.')) > 1 else ''
        except IndexError:
            base_domain_parts = ''
        
        for code in php_code:
            # Find all domains in the code
            found_domains = re.findall(pattern, code)
            unique_findings = []
            
            # Deduplicate findings
            for item in found_domains:
                if item not in domains and item not in unique_findings:
                    unique_findings.append(item)
            
            # Filter and add domains
            for domain in unique_findings:
                if (domain not in domains and 
                    base_domain_parts not in domain and 
                    domain not in exceptions):
                    domains.append(domain)
                    if verbose:
                        self.logger.debug(f"Found domain in PHP code: {domain}")
        
        return domains
    
    def download_php_code(self, link, base_url="", verbose=False):
        """
        Download PHP code from a URL.
        
        Args:
            link (str): Link to the PHP file
            base_url (str): Base URL for resolving relative paths
            verbose (bool): Whether to output verbose information
            
        Returns:
            list: Array of PHP code or None on error
        """
        php_code = []
        
        # Set up request headers
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
        }
        
        try:
            # Resolve URL
            if link.startswith(("http://", "https://", "//")):
                target_url = link
                if link.startswith("//"):
                    target_url = "https:" + link
            else:
                # Handle relative paths
                if base_url:
                    if base_url.endswith('/') and link.startswith('/'):
                        base_url = base_url[:-1]  # Remove trailing slash
                    elif not base_url.endswith('/') and not link.startswith('/'):
                        base_url = base_url + '/'  # Add trailing slash
                    
                    if link.startswith('/'):
                        # Absolute path from domain root
                        parsed_url = base_url.split('://')
                        if len(parsed_url) > 1:
                            protocol = parsed_url[0]
                            domain = parsed_url[1].split('/')[0]
                            target_url = f"{protocol}://{domain}{link}"
                        else:
                            target_url = f"{base_url}{link[1:]}"
                    else:
                        # Relative path
                        target_url = f"{base_url}{link}"
                else:
                    target_url = link
            
            if verbose:
                self.logger.debug(f"Downloading PHP from: {target_url}")
            
            # Send the request
            response = requests.get(target_url, headers=headers)
            
            if response.status_code == 200:
                php_code.append(response.text)
                if verbose:
                    self.logger.debug(f"Successfully downloaded PHP file")
            else:
                if verbose:
                    self.logger.warning(f"Error downloading PHP file: {response.status_code}")
                return None
        except Exception as e:
            if verbose:
                self.logger.error(f"Error downloading PHP file: {str(e)}")
            return None
        
        return php_code
    
    def extract_php_includes(self, php_code, verbose=False):
        """
        Extract PHP include and require statements from the code.
        
        Args:
            php_code (list): List of PHP code strings to analyze
            verbose (bool): Whether to output verbose information
            
        Returns:
            list: List of included/required PHP files
        """
        includes = []
        
        # Patterns for include and require statements
        patterns = [
            r'include(?:_once)?\s*\(\s*[\'"](.+?)[\'"]', 
            r'require(?:_once)?\s*\(\s*[\'"](.+?)[\'"]'
        ]
        
        for code in php_code:
            for pattern in patterns:
                found = re.findall(pattern, code)
                for item in found:
                    if item not in includes:
                        includes.append(item)
                        if verbose:
                            self.logger.debug(f"Found PHP include: {item}")
        
        return includes
    
    def analyze_php_file(self, file_path, base_url="", exceptions=None, verbose=False):
        """
        Analyze a PHP file for external domains and includes.
        
        Args:
            file_path (str): Path to the PHP file or URL
            base_url (str): Base URL for comparison and resolving includes
            exceptions (list): Domains to exclude
            verbose (bool): Whether to output verbose information
            
        Returns:
            dict: Analysis results containing domains and includes
        """
        if exceptions is None:
            exceptions = []
        
        # Download the PHP code
        php_code = self.download_php_code(file_path, base_url, verbose)
        
        if not php_code:
            return {"domains": [], "includes": []}
        
        # Extract domains and includes
        domains = self.extract_embedded_domains(php_code, base_url, exceptions, verbose)
        includes = self.extract_php_includes(php_code, verbose)
        
        return {
            "domains": domains,
            "includes": includes
        }