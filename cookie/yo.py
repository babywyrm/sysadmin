#!/usr/bin/env python3
"""
Firefox Cookie Converter - 2025 Edition - For Doing Beautiful Things
Converts Firefox/Chrome cookies from SQLite to Netscape format.

This script reads cookie databases from Firefox or Chrome browsers and converts
them to the standard Netscape cookie file format that can be used by other tools
like curl, wget, or other HTTP clients.

The Netscape format consists of tab-separated values:
domain, domain_specified, path, secure, expires, name, value
"""

import argparse
import logging
import shutil
import sqlite3
import os,sys,re
import tempfile
from pathlib import Path
from typing import Optional, Tuple, List

# Configure logging with timestamp and level information
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class CookieConverter:
    """
    Handles conversion of browser cookies from SQLite databases to Netscape format.
    
    This class supports both Firefox and Chrome cookie database formats, automatically
    detecting which format is being used and converting accordingly.
    
    Attributes:
        database_path (Path): Path to the input SQLite cookie database
        output_path (Path): Path where the Netscape format output will be written
        host_filter (Optional[str]): Optional hostname filter using SQL LIKE patterns
    """
    
    def __init__(self, database_path: Path, output_path: Path, host_filter: Optional[str] = None):
        """
        Initialize the cookie converter.
        
        Args:
            database_path: Path to the SQLite database containing cookies
            output_path: Path where the converted cookies will be saved
            host_filter: Optional filter to limit cookies by hostname (supports SQL LIKE % wildcards)
        """
        self.database_path = database_path
        self.output_path = output_path
        self.host_filter = host_filter
        
    def _get_firefox_query(self) -> Tuple[str, str, List[str]]:
        """
        Generate SQL query parameters for Firefox cookie database format.
        
        Firefox stores cookies in a table called 'moz_cookies' with specific column names.
        The query selects: host, path, isSecure, expiry, name, value
        
        Returns:
            Tuple containing:
                - SQL query string
                - Column names string
                - Query arguments list for parameterized query
        """
        table = "moz_cookies"
        columns = "host, path, isSecure, expiry, name, value"
        query = f"SELECT {columns} FROM {table}"
        args = []
        
        # Add host filtering if specified
        if self.host_filter:
            query += " WHERE host LIKE ?"
            args.append(self.host_filter)
            
        return query, columns, args
    
    def _get_chrome_query(self) -> Tuple[str, str, List[str]]:
        """
        Generate SQL query parameters for Chrome cookie database format.
        
        Chrome stores cookies in a table called 'cookies' with different column names
        than Firefox. The query selects: host_key, path, secure, expires_utc, name, value
        
        Returns:
            Tuple containing:
                - SQL query string  
                - Column names string
                - Query arguments list for parameterized query
        """
        table = "cookies" 
        columns = "host_key, path, secure, expires_utc, name, value"
        query = f"SELECT {columns} FROM {table}"
        args = []
        
        # Add host filtering if specified (Chrome uses host_key instead of host)
        if self.host_filter:
            query += " WHERE host_key LIKE ?"
            args.append(self.host_filter)
            
        return query, columns, args
    
    def convert(self) -> int:
        """
        Convert cookies from SQLite database to Netscape format file.
        
        This method:
        1. Creates a temporary copy of the database for safety
        2. Attempts to read as Firefox format first, then Chrome if that fails
        3. Writes cookies in Netscape format with proper headers
        4. Cleans up temporary files
        
        The Netscape format uses tab-separated fields:
        domain \t domain_specified \t path \t secure \t expires \t name \t value
        
        Returns:
            int: Number of cookies successfully converted
            
        Raises:
            FileNotFoundError: If the input database file doesn't exist
            sqlite3.Error: If database cannot be read or has unexpected format
            IOError: If output file cannot be written
        """
        # Verify input file exists before proceeding
        if not self.database_path.exists():
            raise FileNotFoundError(f"Database file not found: {self.database_path}")
            
        # Create temporary copy of database to avoid locking the original file
        # This is especially important for Firefox which may have the database open
        with tempfile.NamedTemporaryFile(delete=False, suffix='.sqlite') as temp_file:
            temp_path = Path(temp_file.name)
            
        try:
            # Copy the original database to temporary location
            logger.debug(f"Creating temporary copy of database at {temp_path}")
            shutil.copy2(self.database_path, temp_path)
            
            # Open database connection with context manager for automatic cleanup
            with sqlite3.connect(temp_path) as conn:
                cursor = conn.cursor()
                
                # Attempt to detect browser type by trying Firefox format first
                try:
                    logger.debug("Attempting to read as Firefox cookie format")
                    query, _, args = self._get_firefox_query()
                    cursor.execute(query, args)
                    browser_type = "Firefox"
                except sqlite3.OperationalError as e:
                    # Firefox format failed, try Chrome format
                    logger.info("Firefox format failed, trying Chrome format...")
                    logger.debug(f"Firefox error was: {e}")
                    query, _, args = self._get_chrome_query()
                    cursor.execute(query, args)
                    browser_type = "Chrome"
                
                # Write cookies to output file in Netscape format
                count = 0
                logger.debug(f"Writing cookies to {self.output_path}")
                with self.output_path.open('w', encoding='utf-8') as outfile:
                    # Write standard Netscape cookie file header comments
                    # These comments help identify the file format for other tools
                    outfile.write("# Netscape HTTP Cookie File\n")
                    outfile.write("# Generated by Firefox Cookie Converter\n")
                    outfile.write("# This is a generated file! Do not edit.\n\n")
                    
                    # Process each cookie row from the database
                    for row in cursor.fetchall():
                        # Extract cookie fields - order depends on browser type
                        host, path, secure, expiry, name, value = row
                        
                        # Convert to Netscape format fields
                        # domain_specified is always TRUE for cookies from browsers
                        domain_specified = "TRUE"
                        
                        # Convert secure flag to uppercase string as expected by Netscape format
                        secure_flag = "TRUE" if secure else "FALSE"
                        
                        # Write tab-separated cookie line
                        # Format: domain \t domain_specified \t path \t secure \t expires \t name \t value
                        outfile.write(f"{host}\t{domain_specified}\t{path}\t{secure_flag}\t{expiry}\t{name}\t{value}\n")
                        count += 1
                
                logger.info(f"Successfully converted {count} {browser_type} cookies to {self.output_path}")
                return count
                
        finally:
            # Always clean up temporary file, even if an error occurred
            logger.debug(f"Cleaning up temporary file {temp_path}")
            temp_path.unlink(missing_ok=True)


def main():
    """
    Main entry point for the cookie converter script.
    
    This function:
    1. Sets up command line argument parsing
    2. Configures logging based on verbosity level
    3. Creates and runs the cookie converter
    4. Handles errors and exit codes appropriately
    
    The script supports both Firefox and Chrome cookie databases and can filter
    by hostname using SQL LIKE patterns (% wildcards).
    """
    # Set up command line argument parser with detailed help
    parser = argparse.ArgumentParser(
        description="Convert Firefox/Chrome cookies to Netscape format",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --database ~/.mozilla/firefox/profile/cookies.sqlite --output cookies.txt
  %(prog)s -d cookies.sqlite -o output.txt --host "%%.example.com"
  %(prog)s -d cookies.sqlite -o output.txt --host "github.com" --verbose
  
Notes:
  - The script automatically detects Firefox vs Chrome database format
  - Host filtering supports SQL LIKE patterns (use %% for wildcards)
  - Output is in standard Netscape cookie format for use with curl, wget, etc.
        """
    )
    
    # Define command line arguments
    parser.add_argument(
        "-d", "--database",
        type=Path,
        required=True,
        help="Path to Firefox/Chrome SQLite cookie database file"
    )
    
    parser.add_argument(
        "-o", "--output", 
        type=Path,
        required=True,
        help="Output file path for Netscape format cookies"
    )
    
    parser.add_argument(
        "--host",
        help="Filter cookies by hostname (supports SQL LIKE patterns with %% wildcards)"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true", 
        help="Enable verbose logging output"
    )
    
    # Parse command line arguments
    args = parser.parse_args()
    
    # Configure logging level based on verbosity flag
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled")
    
    try:
        # Create converter instance with parsed arguments
        converter = CookieConverter(args.database, args.output, args.host)
        
        # Perform the conversion
        count = converter.convert()
        
        # Report success to user
        print(f"Successfully exported {count} cookies to '{args.output}'")
        
    except Exception as e:
        # Log error details and exit with error code
        logger.error(f"Conversion failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
