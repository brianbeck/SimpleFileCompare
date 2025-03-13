#!/usr/bin/env python3
"""
File Hash Comparison Tool

This script hashes files using a specified algorithm, stores the hashes in a database,
and optionally moves files to a specified directory.
"""

import os
import sys
import hashlib
import argparse
import csv
import shutil
import logging
from datetime import datetime
from typing import List, Dict, Optional, Set, Tuple
import concurrent.futures

# Optional database imports - will be imported only if database connection is requested
try:
    import mysql.connector  # For MariaDB
    MARIADB_AVAILABLE = True
except ImportError:
    MARIADB_AVAILABLE = False

try:
    import psycopg2  # For PostgreSQL
    POSTGRESQL_AVAILABLE = True
except ImportError:
    POSTGRESQL_AVAILABLE = False


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='File Hash Comparison Tool')
    
    # File selection options
    parser.add_argument('paths', nargs='+', help='Files or directories to process')
    parser.add_argument('--extensions', '-e', nargs='+', default=None, 
                        help='File extensions to include (e.g., jpg png)')
    
    # Hash options
    parser.add_argument('--algorithm', '-a', choices=['md5', 'sha1', 'sha256', 'sha512'], 
                        default='sha256', help='Hash algorithm to use')
    
    # Database options
    parser.add_argument('--db-type', choices=['csv', 'mariadb', 'postgresql'], 
                        default='csv', help='Database type to use')
    parser.add_argument('--db-host', help='Database host')
    parser.add_argument('--db-port', type=int, help='Database port')
    parser.add_argument('--db-name', help='Database name')
    parser.add_argument('--db-user', help='Database username')
    parser.add_argument('--db-password', help='Database password')
    
    # Output options
    parser.add_argument('--output', '-o', help='Output CSV file (if db-type is csv)')
    parser.add_argument('--move-to', help='Directory to move files to')
    parser.add_argument('--move-duplicates', action='store_true', 
                        help='Move only duplicate files (requires database with existing entries)')
    
    # Performance options
    parser.add_argument('--threads', '-t', type=int, default=os.cpu_count(), 
                        help='Number of threads to use for hashing')
    
    # Verbosity
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.db_type != 'csv' and (not args.db_host or not args.db_name or not args.db_user):
        parser.error("Database connection requires --db-host, --db-name, and --db-user")
    
    if args.db_type == 'csv' and not args.output:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        args.output = f"file_hashes_{timestamp}.csv"
        logger.info(f"No output file specified, using: {args.output}")
    
    if args.move_to and not os.path.exists(args.move_to):
        try:
            os.makedirs(args.move_to)
            logger.info(f"Created directory: {args.move_to}")
        except OSError as e:
            parser.error(f"Failed to create directory {args.move_to}: {e}")
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    return args


def get_file_list(paths: List[str], extensions: Optional[List[str]] = None) -> List[str]:
    """
    Get a list of files from the provided paths, optionally filtered by extensions.
    
    Args:
        paths: List of file or directory paths
        extensions: Optional list of file extensions to include (without the dot)
    
    Returns:
        List of file paths
    """
    file_list = []
    ext_set = set(ext.lower().lstrip('.') for ext in extensions) if extensions else None
    
    for path in paths:
        if os.path.isfile(path):
            if not ext_set or os.path.splitext(path)[1].lower().lstrip('.') in ext_set:
                file_list.append(os.path.abspath(path))
        elif os.path.isdir(path):
            for root, _, files in os.walk(path):
                for file in files:
                    if not ext_set or os.path.splitext(file)[1].lower().lstrip('.') in ext_set:
                        file_list.append(os.path.abspath(os.path.join(root, file)))
        else:
            logger.warning(f"Path not found: {path}")
    
    return file_list


def calculate_file_hash(file_path: str, algorithm: str) -> Optional[str]:
    """
    Calculate the hash of a file using the specified algorithm.
    
    Args:
        file_path: Path to the file
        algorithm: Hash algorithm to use (md5, sha1, sha256, sha512)
    
    Returns:
        File hash as a hexadecimal string, or None if an error occurred
    """
    hash_func = getattr(hashlib, algorithm)()
    
    try:
        with open(file_path, 'rb') as f:
            # Read the file in chunks to handle large files efficiently
            for chunk in iter(lambda: f.read(4096), b''):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except (IOError, OSError) as e:
        logger.error(f"Error hashing file {file_path}: {e}")
        return None


def process_file(file_path: str, algorithm: str) -> Tuple[str, Optional[str]]:
    """
    Process a single file by calculating its hash.
    
    Args:
        file_path: Path to the file
        algorithm: Hash algorithm to use
    
    Returns:
        Tuple of (file_path, hash)
    """
    file_hash = calculate_file_hash(file_path, algorithm)
    if file_hash:
        logger.debug(f"Processed {file_path}: {file_hash}")
    return (file_path, file_hash)


def connect_to_database(args):
    """
    Connect to the specified database.
    
    Args:
        args: Command line arguments
    
    Returns:
        Database connection object or None if using CSV
    """
    if args.db_type == 'csv':
        return None
    
    try:
        if args.db_type == 'mariadb':
            if not MARIADB_AVAILABLE:
                logger.error("MariaDB support requires mysql-connector-python package")
                sys.exit(1)
            
            conn = mysql.connector.connect(
                host=args.db_host,
                port=args.db_port or 3306,
                database=args.db_name,
                user=args.db_user,
                password=args.db_password
            )
            logger.info(f"Connected to MariaDB database: {args.db_name}")
            return conn
        
        elif args.db_type == 'postgresql':
            if not POSTGRESQL_AVAILABLE:
                logger.error("PostgreSQL support requires psycopg2 package")
                sys.exit(1)
            
            conn = psycopg2.connect(
                host=args.db_host,
                port=args.db_port or 5432,
                dbname=args.db_name,
                user=args.db_user,
                password=args.db_password
            )
            logger.info(f"Connected to PostgreSQL database: {args.db_name}")
            return conn
    
    except Exception as e:
        logger.error(f"Database connection error: {e}")
        sys.exit(1)


def test_database_connection(args):
    """
    Test the database connection at the start of the program.
    
    Args:
        args: Command line arguments
    
    Returns:
        True if connection is successful or using CSV, False otherwise
    """
    if args.db_type == 'csv':
        return True
    
    try:
        logger.info(f"Testing connection to {args.db_type} database...")
        
        if args.db_type == 'mariadb':
            if not MARIADB_AVAILABLE:
                logger.error("MariaDB support requires mysql-connector-python package")
                return False
            
            conn = mysql.connector.connect(
                host=args.db_host,
                port=args.db_port or 3306,
                database=args.db_name,
                user=args.db_user,
                password=args.db_password
            )
        
        elif args.db_type == 'postgresql':
            if not POSTGRESQL_AVAILABLE:
                logger.error("PostgreSQL support requires psycopg2 package")
                return False
            
            conn = psycopg2.connect(
                host=args.db_host,
                port=args.db_port or 5432,
                dbname=args.db_name,
                user=args.db_user,
                password=args.db_password
            )
        
        # Test if we can execute a simple query
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.close()
        conn.close()
        
        logger.info("Database connection test successful")
        return True
    
    except Exception as e:
        logger.error(f"Database connection test failed: {e}")
        return False


def create_table_if_not_exists(conn, db_type):
    """
    Create the file_hashes table if it doesn't exist.
    
    Args:
        conn: Database connection
        db_type: Database type ('mariadb' or 'postgresql')
    """
    cursor = conn.cursor()
    
    if db_type == 'mariadb':
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS file_hashes (
                id INT AUTO_INCREMENT PRIMARY KEY,
                file_hash VARCHAR(128) NOT NULL,
                file_name VARCHAR(255) NOT NULL,
                file_path VARCHAR(1024) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX (file_hash)
            )
        """)
    elif db_type == 'postgresql':
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS file_hashes (
                id SERIAL PRIMARY KEY,
                file_hash VARCHAR(128) NOT NULL,
                file_name VARCHAR(255) NOT NULL,
                file_path VARCHAR(1024) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                CONSTRAINT file_hash_idx UNIQUE (file_hash, file_path)
            );
            CREATE INDEX IF NOT EXISTS file_hash_idx ON file_hashes (file_hash);
        """)
    
    conn.commit()
    cursor.close()


def get_existing_hashes(conn, db_type):
    """
    Get existing hashes from the database.
    
    Args:
        conn: Database connection
        db_type: Database type
    
    Returns:
        Dictionary mapping hashes to lists of file paths
    """
    if not conn:
        return {}
    
    existing_hashes = {}
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT file_hash, file_path FROM file_hashes")
        for file_hash, file_path in cursor.fetchall():
            if file_hash not in existing_hashes:
                existing_hashes[file_hash] = []
            existing_hashes[file_hash].append(file_path)
    except Exception as e:
        logger.error(f"Error retrieving existing hashes: {e}")
    finally:
        cursor.close()
    
    return existing_hashes


def save_to_csv(file_data: List[Dict], output_file: str):
    """
    Save file hash data to a CSV file.
    
    Args:
        file_data: List of dictionaries containing file hash data
        output_file: Path to the output CSV file
    """
    try:
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['file_hash', 'file_name', 'file_path'])
            writer.writeheader()
            writer.writerows(file_data)
        logger.info(f"Saved {len(file_data)} records to {output_file}")
    except IOError as e:
        logger.error(f"Error writing to CSV file: {e}")


def save_to_database(conn, db_type, file_data):
    """
    Save file hash data to the database.
    
    Args:
        conn: Database connection
        db_type: Database type
        file_data: List of dictionaries containing file hash data
    """
    if not conn:
        return
    
    cursor = conn.cursor()
    
    try:
        if db_type == 'mariadb':
            for data in file_data:
                cursor.execute(
                    "INSERT INTO file_hashes (file_hash, file_name, file_path) VALUES (%s, %s, %s)",
                    (data['file_hash'], data['file_name'], data['file_path'])
                )
        elif db_type == 'postgresql':
            for data in file_data:
                cursor.execute(
                    """
                    INSERT INTO file_hashes (file_hash, file_name, file_path)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (file_hash, file_path) DO NOTHING
                    """,
                    (data['file_hash'], data['file_name'], data['file_path'])
                )
        
        conn.commit()
        logger.info(f"Saved {len(file_data)} records to database")
    except Exception as e:
        conn.rollback()
        logger.error(f"Database error: {e}")
    finally:
        cursor.close()


def move_files(file_data, move_to, existing_hashes=None, move_duplicates=False):
    """
    Move files to the specified directory.
    
    Args:
        file_data: List of dictionaries containing file hash data
        move_to: Directory to move files to
        existing_hashes: Dictionary of existing hashes (for duplicate detection)
        move_duplicates: Whether to move only duplicate files
    
    Returns:
        Number of files moved
    """
    if not move_to:
        return 0
    
    moved_count = 0
    
    for data in file_data:
        file_hash = data['file_hash']
        file_path = data['file_path']
        
        # Skip if we're only moving duplicates and this isn't a duplicate
        if move_duplicates and existing_hashes and (
            file_hash not in existing_hashes or 
            len(existing_hashes[file_hash]) <= 1
        ):
            continue
        
        # Create a unique filename in the destination directory
        file_name = os.path.basename(file_path)
        dest_path = os.path.join(move_to, file_name)
        
        # Handle filename collisions by adding the hash
        if os.path.exists(dest_path):
            name, ext = os.path.splitext(file_name)
            dest_path = os.path.join(move_to, f"{name}_{file_hash[:8]}{ext}")
        
        try:
            shutil.move(file_path, dest_path)
            logger.info(f"Moved: {file_path} -> {dest_path}")
            moved_count += 1
        except (IOError, OSError) as e:
            logger.error(f"Error moving file {file_path}: {e}")
    
    return moved_count


def main():
    """Main function."""
    args = parse_arguments()
    
    # Test database connection if using a database
    if args.db_type != 'csv':
        if not test_database_connection(args):
            logger.error(f"Failed to connect to {args.db_type} database. Exiting.")
            sys.exit(1)
    
    # Get list of files to process
    logger.info("Gathering file list...")
    file_list = get_file_list(args.paths, args.extensions)
    logger.info(f"Found {len(file_list)} files to process")
    
    if not file_list:
        logger.warning("No files found to process")
        return
    
    # Connect to database if needed
    conn = connect_to_database(args)
    if conn and args.db_type != 'csv':
        create_table_if_not_exists(conn, args.db_type)
    
    # Get existing hashes if we need to check for duplicates
    existing_hashes = {}
    if args.move_duplicates and conn:
        existing_hashes = get_existing_hashes(conn, args.db_type)
        logger.info(f"Retrieved {len(existing_hashes)} existing hashes from database")
    
    # Process files in parallel
    logger.info(f"Processing files using {args.threads} threads...")
    file_data = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_file = {
            executor.submit(process_file, file_path, args.algorithm): file_path
            for file_path in file_list
        }
        
        for future in concurrent.futures.as_completed(future_to_file):
            file_path, file_hash = future.result()
            if file_hash:
                file_data.append({
                    'file_hash': file_hash,
                    'file_name': os.path.basename(file_path),
                    'file_path': file_path
                })
    
    logger.info(f"Successfully processed {len(file_data)} files")
    
    # Save results
    if args.db_type == 'csv':
        save_to_csv(file_data, args.output)
    else:
        save_to_database(conn, args.db_type, file_data)
    
    # Move files if requested
    if args.move_to:
        moved_count = move_files(
            file_data, 
            args.move_to, 
            existing_hashes=existing_hashes, 
            move_duplicates=args.move_duplicates
        )
        logger.info(f"Moved {moved_count} files to {args.move_to}")
    
    # Clean up
    if conn:
        conn.close()
        logger.info("Database connection closed")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)
