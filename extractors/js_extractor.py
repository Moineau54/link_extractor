#!/usr/bin/env python3
"""
JavaScript Extractor - A module for extracting domains from JavaScript files

This module downloads and analyzes JavaScript files to extract domain references,
helping security researchers and web developers identify external dependencies.
"""

import re
import requests
import logging


class JsExtractor:
    """
    Class for extracting and analyzing JavaScript files from web pages.
    """
    
    def __init__(self):
        """Initialize the JavaScript extractor."""
        self.logger = logging.getLogger('link_extractor.js')
    
    def extract_embedded_domains(self, js_code, url, exceptions, verbose=False):
        """
        Extract domains from JavaScript code using regex.
        
        Args:
            js_code (list): List of JavaScript code strings to analyze
            url (str): Base URL for comparison
            exceptions (list): Domains to exclude
            verbose (bool): Whether to output verbose information
            
        Returns:
            list: List of extracted domains
        """
        domains = []
        
        # Pattern to extract domains from URLs
        # pattern = r'https?:\/\/(?:www\.)?([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,})'
        pattern = r'https?:\/\/(?:[a-zA-Z0-9-]{1,10}\.)?([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,})'

        # Get base domain for comparison
        try:
            base_domain_parts = url.split('.')[1] if len(url.split('.')) > 1 else ''
        except IndexError:
            base_domain_parts = ''
        
        # Process each JavaScript code string
        for code in js_code:
            # Find all domains in the code
            found_domains = re.findall(pattern, code)
            unique_findings = []
            
            # Deduplicate findings
            for item in found_domains:
                if item not in domains and item not in unique_findings and item not in exceptions and item.__contains__(base_domain_parts) == False:
                    unique_findings.append(item)
            
            # Filter and add domains
            for domain in unique_findings:
                if (domain not in domains and domain.__contains__(base_domain_parts) == False and 
                    domain not in exceptions):
                    domains.append(domain)
                    if verbose:
                        self.logger.debug(f"Found domain in JS code: {domain}")
        
        return domains
    
    def download_js_code(self, link, base_url="", verbose=False):
        """
        Download JavaScript code from a URL.
        
        Args:
            link (str): Link to the JavaScript file
            base_url (str): Base URL for resolving relative paths
            verbose (bool): Whether to output verbose information
            
        Returns:
            list: Array of JavaScript code or None on error
        """
        js_code = []
        
        # Set up request headers
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/javascript,application/javascript,*/*;q=0.9',
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
                self.logger.debug(f"Downloading JS from: {target_url}")
            
            # Send the request
            response = requests.get(target_url, headers=headers)
            
            if response.status_code == 200:
                js_code.append(response.text)
                if verbose:
                    self.logger.debug(f"Successfully downloaded JS file")
            else:
                if verbose:
                    self.logger.warning(f"Error downloading JS file: {response.status_code}")
                return None
        except Exception as e:
            if verbose:
                self.logger.error(f"Error downloading JS file: {str(e)}")
            return None
        
        return js_code