#!/usr/bin/env python3
"""
Database Utility - A module for managing domain information storage

This module handles the database operations for the Link Extractor tool,
including creating connections, tables, and managing domain entries.
"""

import sqlite3
from sqlite3 import Error
import logging


class Database:
    """Class for managing database operations."""
    
    def __init__(self, verbose=False):
        """
        Initialize the database manager.
        
        Args:
            verbose (bool): Whether to output verbose information
        """
        self.verbose = verbose
        self.logger = logging.getLogger('link_extractor.db')
    
    def create_connection(self, db_file='domains.db'):
        """
        Create a database connection to a SQLite database.
        
        Args:
            db_file (str): Database file path
            
        Returns:
            sqlite3.Connection: Database connection object or None on error
        """
        conn = None
        try:
            conn = sqlite3.connect(db_file)
            if self.verbose:
                self.logger.info(f"Connected to database: {db_file}")
            return conn
        except Error as e:
            self.logger.error(f"Error connecting to database: {e}")
        return conn
    
    def create_table(self, conn):
        """
        Create a table if it doesn't exist.
        
        Args:
            conn (sqlite3.Connection): Database connection object
        """
        try:
            c = conn.cursor()
            c.execute('''CREATE TABLE IF NOT EXISTS domains
                         (id INTEGER PRIMARY KEY, 
                          domain TEXT NOT NULL, 
                          occurrences INTEGER NOT NULL, 
                          is_tracker BOOLEAN NOT NULL, 
                          origin TEXT)''')
            if self.verbose:
                self.logger.info("Table 'domains' checked/created")
        except Error as e:
            self.logger.error(f"Error creating table: {e}")
    
    def modify_entry(self, conn, domain, occurrences, is_tracker, url):
        """
        Modify an entry if the domain already exists or insert a new one.

        Args:
            conn (sqlite3.Connection): Database connection object
            domain (str): The domain to modify or insert
            occurrences (int): Number of occurrences to record
            is_tracker (bool): Whether the domain is a tracker
            url (str): The URL where the domain was found
        """
        c = conn.cursor()
        
        # Extract origin from the URL
        try:
            origin = url.split("/")[2]
        except IndexError:
            # Handle cases where URL might not have the expected format
            origin = url
        
        # First check if domain exists
        c.execute("SELECT * FROM domains WHERE domain = ?", (domain,))
        existing_record = c.fetchone()
        
        # Determine the new origin value
        if existing_record is not None:
            # If domain exists in DB
            origin_db = existing_record[4]  # Assuming the origin is in the 5th column (index 4)
            
            # Check if origin_db is None before proceeding
            if origin_db:
                # Check if the origin is already in the origin_db string
                if origin in origin_db:
                    # Origin already exists, don't update it
                    new_origin = origin_db
                else:
                    # Add the new origin to the existing ones
                    new_origin = f"{origin_db}, {origin}"
            else:
                # If origin_db is None, just use the current origin
                new_origin = origin
        else:
            # New domain
            new_origin = origin
        
        # Insert or update based on whether domain exists
        if existing_record is None:
            # Insert new domain
            c.execute("INSERT INTO domains (domain, occurrences, is_tracker, origin) VALUES (?, ?, ?, ?)", 
                    (domain, occurrences, is_tracker, new_origin))
            if self.verbose:
                self.logger.info(f"Inserted new domain: {domain} with occurrences: {occurrences} and is_tracker: {is_tracker}")
        else:
            # Update existing domain - only update origin if it changed
            if existing_record[4] != new_origin:
                c.execute("UPDATE domains SET occurrences = occurrences + 1, origin = ? WHERE domain = ?", 
                        (new_origin, domain))
                if self.verbose:
                    self.logger.info(f"Updated domain: {domain}, incremented occurrences and updated origin")
        
        conn.commit()
    
    def insert_entry(self, conn, domain, occurrences, is_tracker, url, verbose=False):
        """
        Insert a new entry or modify an existing one.

        Checks if the domain is listed in the exceptions file and deletes it if found.

        Args:
            conn (sqlite3.Connection): Database connection object
            domain (str): The domain to insert or modify
            occurrences (int): Number of occurrences to record
            is_tracker (bool): Whether the domain is a tracker
            url (str): The URL where the domain was found
            verbose (bool): Whether to print verbose output
        """
        # Read exceptions file once and store the domains
        try:
            with open("exceptions.txt", "r") as f:
                domain_exceptions = {line.strip() for line in f.readlines() if line.strip()}
        except Exception as e:
            self.logger.error(f"Error reading exceptions file: {e}")
            domain_exceptions = set()

        if domain in domain_exceptions:
            # If domain is in exceptions, delete it from the database
            c = conn.cursor()
            c.execute("DELETE FROM domains WHERE domain = ?", (domain,))
            if c.rowcount > 0 and (verbose or self.verbose):
                self.logger.info(f"Deleted domain {domain} as it is in exceptions list")
            conn.commit()
            return  # Exit the function since we've deleted the domain
        
        # Check if domain contains "js." and set is_tracker to False as it's unlikely to be a tracker
        if "js." in domain:
            is_tracker = False
            c = conn.cursor()
            c.execute("SELECT * FROM domains WHERE domain = ?", (domain,))
            if c.fetchone():
                c.execute("UPDATE domains SET is_tracker = 0 WHERE domain = ?", (domain,))
                conn.commit()

                if verbose or self.verbose:
                    self.logger.info(f"Domain {domain} contains 'js.', setting is_tracker to False")
                
        # Call the modify_entry method to handle both insert and update logic
        if is_tracker:
            self.modify_entry(conn, domain, occurrences, is_tracker, url)
    
    def delete_exceptions(self, conn):
        """
        Delete all domains that are listed in the exceptions file.
        
        Args:
            conn (sqlite3.Connection): Database connection object
        """
        try:
            # Read exceptions file
            with open("exceptions.txt", "r") as f:
                domain_exceptions = {line.strip() for line in f.readlines() if line.strip()}
            
            if not domain_exceptions:
                if self.verbose:
                    self.logger.info("No exceptions found in exceptions.txt")
                return
            
            c = conn.cursor()
            
            # Count how many will be deleted for reporting
            placeholders = ', '.join(['?'] * len(domain_exceptions))
            c.execute(f"SELECT COUNT(*) FROM domains WHERE domain IN ({placeholders})", 
                     list(domain_exceptions))
            count = c.fetchone()[0]
            
            # Delete all domains in the exceptions list
            c.execute(f"DELETE FROM domains WHERE domain IN ({placeholders})", 
                     list(domain_exceptions))
            
            conn.commit()
            
            if self.verbose:
                self.logger.info(f"Deleted {count} domains that were in the exceptions list")
                
        except Error as e:
            self.logger.error(f"Error deleting exceptions: {e}")
    
    def select_all_domains(self, conn):
        """
        Query all rows in the domains table.
        
        Args:
            conn (sqlite3.Connection): Database connection object
            
        Returns:
            list: List of domain records
        """
        c = conn.cursor()
        c.execute("SELECT * FROM domains")
        rows = c.fetchall()
        if self.verbose:
            self.logger.info(f"Retrieved {len(rows)} rows from the 'domains' table")
        return rows
    
    def display_domains_table(self, conn, limit=None):
        """
        Display the domains table in a formatted way.
        
        Args:
            conn (sqlite3.Connection): Database connection object
            limit (int, optional): Limit the number of rows to display
        """
        c = conn.cursor()
        if limit:
            c.execute("SELECT * FROM domains ORDER BY occurrences DESC LIMIT ?", (limit,))
        else:
            c.execute("SELECT * FROM domains ORDER BY occurrences DESC")
            
        rows = c.fetchall()
        
        if not rows:
            self.logger.info("No domains found in the database")
            return
            
        # Calculate max lengths for each column for better formatting
        id_len = max(len(str(row[0])) for row in rows)
        domain_len = max(len(str(row[1])) for row in rows)
        occurrences_len = max(len(str(row[2])) for row in rows)
        tracker_len = 10  # Fixed length for boolean
        origin_len = 30  # Cap at 30 chars
        
        # Print header
        header = (f"{'ID':<{id_len}} | {'Domain':<{domain_len}} | {'Count':<{occurrences_len}} | "
                 f"{'Tracker':<{tracker_len}} | {'Origin':<{origin_len}}")
        self.logger.info(header)
        
        # Print separator
        separator = '-' * (id_len + domain_len + occurrences_len + tracker_len + origin_len + 8)
        self.logger.info(separator)
        
        # Print rows
        for row in rows:
            # Format the origin to fit in the allocated space
            origin = str(row[4] or "")
            if len(origin) > origin_len:
                origin = origin[:origin_len-3] + "..."
                
            self.logger.info(
                f"{row[0]:<{id_len}} | {row[1]:<{domain_len}} | {row[2]:<{occurrences_len}} | "
                f"{'Yes' if row[3] else 'No':<{tracker_len}} | {origin:<{origin_len}}"
            )
            
        self.logger.info(f"Total domains: {len(rows)}")