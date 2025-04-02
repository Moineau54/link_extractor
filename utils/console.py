#!/usr/bin/env python3
"""
Console Utility - A module for console output formatting

This module provides utilities for displaying formatted output in the console,
including colors, headers, and other visual elements.
"""

import shutil
import logging


class ConsoleHelper:
    """Class for handling console output formatting."""
    
    # ANSI color codes for terminal output formatting
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'
    
    def __init__(self, verbose=False):
        """
        Initialize the console helper.
        
        Args:
            verbose (bool): Whether to output verbose information
        """
        self.verbose = verbose
        self.logger = logging.getLogger('link_extractor.console')
        self.app_name = "Link Extractor"
        self.version = "2.2.4"
    
    def display_banner(self, verbose=False):
        """
        Display an adaptive menu header in the terminal.
        
        Args:
            verbose (bool): Whether verbose mode is enabled
        """
        # Get terminal size
        term_width = shutil.get_terminal_size().columns
        
        # Calculate available space, ensuring minimum width
        # Setting minimum width to 40 characters
        width = max(40, min(term_width - 2, 80))  # Max width capped at 80
        
        # Create dynamic border based on terminal width
        border = "=" * width
        
        # Calculate padding for centered text
        name_padding = (width - len(self.app_name)) // 2
        version_padding = (width - len(f"v: {self.version}")) // 2
        
        # Format for verbose mode indicator
        verbose_text = ""
        if verbose:
            verbose_text = f"{self.CYAN}Verbose mode enabled{self.END}"
            # Calculate padding taking ANSI color codes into account
            visible_len = len("Verbose mode enabled")  # Length without ANSI codes
            verbose_padding = (width - visible_len) // 2
        
        # Print menu with dynamic width
        print(f"+{border}+")
        print(f"|{' ' * width}|")
        print(f"|{' ' * name_padding}{self.BOLD}{self.app_name}{self.END}{' ' * (width - name_padding - len(self.app_name))}|")
        print(f"|{' ' * version_padding}v: {self.GREEN}{self.version}{self.END}{' ' * (width - version_padding - len('v: ') - len(self.version))}|")
        print(f"|{' ' * width}|")
        if verbose:
            print(f"|{' ' * verbose_padding}{verbose_text}{' ' * (width - verbose_padding - visible_len)}|")
        print(f"|{' ' * width}|")
        print(f"+{border}+")
    
    def create_dynamic_border(self, text, term_width=None):
        """
        Create a dynamic border that fits the terminal width.
        
        Args:
            text (str): The text to be displayed (used to calculate width)
            term_width (int, optional): Terminal width, detected automatically if None
        
        Returns:
            str: A string of "=" characters that fits the terminal width
        """
        if not term_width:
            term_width = shutil.get_terminal_size().columns
        
        # Ensure minimum width of 40, maximum of terminal width
        width = max(40, min(term_width - 2, 80))
        border = "=" * width
        
        return border
    
    def print_info(self, message):
        """
        Print an info message with cyan color.
        
        Args:
            message (str): The message to print
        """
        print(f"{self.CYAN}{message}{self.END}")
        self.logger.info(message)
    
    def print_success(self, message):
        """
        Print a success message with green color.
        
        Args:
            message (str): The message to print
        """
        print(f"{self.GREEN}{message}{self.END}")
        self.logger.info(message)
    
    def print_warning(self, message):
        """
        Print a warning message with yellow color.
        
        Args:
            message (str): The message to print
        """
        print(f"{self.YELLOW}{message}{self.END}")
        self.logger.warning(message)
    
    def print_error(self, message):
        """
        Print an error message with red color.
        
        Args:
            message (str): The message to print
        """
        print(f"{self.RED}{message}{self.END}")
        self.logger.error(message)
    
    def print_debug(self, message):
        """
        Print a debug message with blue color if verbose mode is enabled.
        
        Args:
            message (str): The message to print
        """
        if self.verbose:
            print(f"{self.BLUE}{message}{self.END}")
            self.logger.debug(message)
