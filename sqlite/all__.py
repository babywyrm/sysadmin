#!/usr/bin/env python3
"""
Robust SQLite Database Management Script
Provides comprehensive database operations, schema management, and utilities
"""

import sqlite3
import json
import csv
import os
import shutil
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional, Union, Tuple
from datetime import datetime
import argparse
import logging


class SQLiteManager:
    """Comprehensive SQLite database management class"""
    
    def __init__(self, database_path: str, timeout: float = 30.0):
        """
        Initialize SQLite manager
        
        Args:
            database_path: Path to SQLite database file
            timeout: Connection timeout in seconds
        """
        self.database_path = Path(database_path)
        self.timeout = timeout
        self.connection: Optional[sqlite3.Connection] = None
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        
    def connect(self) -> sqlite3.Connection:
        """Create and return database connection"""
        if self.connection is None:
            self.connection = sqlite3.connect(
                str(self.database_path),
                timeout=self.timeout,
                check_same_thread=False
            )
            # Enable foreign keys
            self.connection.execute("PRAGMA foreign_keys = ON")
            # Set row factory for dictionary-like access
            self.connection.row_factory = sqlite3.Row
            
        return self.connection
    
    def disconnect(self) -> None:
        """Close database connection"""
        if self.connection:
            self.connection.close()
            self.connection = None
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.disconnect()
    
    # Database Information Methods
    
    def get_database_info(self) -> Dict[str, Any]:
        """Get comprehensive database information"""
        conn = self.connect()
        cursor = conn.cursor()
        
        info = {
            'database_path': str(self.database_path),
            'file_size_mb': self.get_file_size(),
            'page_count': None,
            'page_size': None,
            'schema_version': None,
            'user_version': None,
            'tables': [],
            'indexes': [],
            'triggers': [],
            'views': []
        }
        
        try:
            # Get PRAGMA information
            cursor.execute("PRAGMA page_count")
            info['page_count'] = cursor.fetchone()[0]
            
            cursor.execute("PRAGMA page_size")
            info['page_size'] = cursor.fetchone()[0]
            
            cursor.execute("PRAGMA schema_version")
            info['schema_version'] = cursor.fetchone()[0]
            
            cursor.execute("PRAGMA user_version")
            info['user_version'] = cursor.fetchone()[0]
            
            # Get schema objects
            cursor.execute("""
                SELECT name, type, sql 
                FROM sqlite_master 
                WHERE type IN ('table', 'index', 'trigger', 'view')
                ORDER BY type, name
            """)
            
            for row in cursor.fetchall():
                obj = {
                    'name': row['name'],
                    'sql': row['sql']
                }
                
                if row['type'] == 'table':
                    info['tables'].append(obj)
                elif row['type'] == 'index':
                    info['indexes'].append(obj)
                elif row['type'] == 'trigger':
                    info['triggers'].append(obj)
                elif row['type'] == 'view':
                    info['views'].append(obj)
                    
        except sqlite3.Error as e:
            self.logger.error(f"Error getting database info: {e}")
            
        return info
    
    def get_file_size(self) -> float:
        """Get database file size in MB"""
        try:
            if self.database_path.exists():
                return self.database_path.stat().st_size / (1024 * 1024)
            return 0.0
        except OSError:
            return 0.0
    
    def get_table_info(self, table_name: str) -> Dict[str, Any]:
        """Get detailed information about a specific table"""
        conn = self.connect()
        cursor = conn.cursor()
        
        info = {
            'name': table_name,
            'exists': False,
            'columns': [],
            'indexes': [],
            'row_count': 0,
            'foreign_keys': []
        }
        
        try:
            # Check if table exists
            cursor.execute("""
                SELECT COUNT(*) FROM sqlite_master 
                WHERE type='table' AND name=?
            """, (table_name,))
            
            if cursor.fetchone()[0] == 0:
                return info
                
            info['exists'] = True
            
            # Get column information
            cursor.execute(f"PRAGMA table_info({table_name})")
            for row in cursor.fetchall():
                info['columns'].append({
                    'cid': row['cid'],
                    'name': row['name'],
                    'type': row['type'],
                    'not_null': bool(row['notnull']),
                    'default_value': row['dflt_value'],
                    'primary_key': bool(row['pk'])
                })
            
            # Get indexes
            cursor.execute(f"PRAGMA index_list({table_name})")
            for row in cursor.fetchall():
                info['indexes'].append({
                    'name': row['name'],
                    'unique': bool(row['unique']),
                    'origin': row['origin']
                })
            
            # Get foreign keys
            cursor.execute(f"PRAGMA foreign_key_list({table_name})")
            for row in cursor.fetchall():
                info['foreign_keys'].append({
                    'id': row['id'],
                    'seq': row['seq'],
                    'table': row['table'],
                    'from_column': row['from'],
                    'to_column': row['to'],
                    'on_update': row['on_update'],
                    'on_delete': row['on_delete']
                })
            
            # Get row count
            cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
            info['row_count'] = cursor.fetchone()[0]
            
        except sqlite3.Error as e:
            self.logger.error(f"Error getting table info for {table_name}: {e}")
            
        return info
    
    def list_tables(self) -> List[str]:
        """Get list of all tables in database"""
        conn = self.connect()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name NOT LIKE 'sqlite_%'
                ORDER BY name
            """)
            return [row['name'] for row in cursor.fetchall()]
        except sqlite3.Error as e:
            self.logger.error(f"Error listing tables: {e}")
            return []
    
    # Table Management Methods
    
    def create_table(self, table_name: str, columns: List[Dict[str, str]], 
                    constraints: Optional[List[str]] = None) -> bool:
        """
        Create a new table
        
        Args:
            table_name: Name of the table
            columns: List of column definitions [{'name': 'col1', 'type': 'TEXT', 'constraints': 'NOT NULL'}]
            constraints: List of table-level constraints
        """
        conn = self.connect()
        cursor = conn.cursor()
        
        try:
            column_defs = []
            for col in columns:
                col_def = f"{col['name']} {col['type']}"
                if 'constraints' in col:
                    col_def += f" {col['constraints']}"
                column_defs.append(col_def)
            
            if constraints:
                column_defs.extend(constraints)
            
            sql = f"CREATE TABLE {table_name} ({', '.join(column_defs)})"
            cursor.execute(sql)
            conn.commit()
            
            self.logger.info(f"Created table: {table_name}")
            return True
            
        except sqlite3.Error as e:
            self.logger.error(f"Error creating table {table_name}: {e}")
            conn.rollback()
            return False
    
    def drop_table(self, table_name: str) -> bool:
        """Drop a table"""
        conn = self.connect()
        cursor = conn.cursor()
        
        try:
            cursor.execute(f"DROP TABLE IF EXISTS {table_name}")
            conn.commit()
            self.logger.info(f"Dropped table: {table_name}")
            return True
            
        except sqlite3.Error as e:
            self.logger.error(f"Error dropping table {table_name}: {e}")
            conn.rollback()
            return False
    
    def rename_table(self, old_name: str, new_name: str) -> bool:
        """Rename a table"""
        conn = self.connect()
        cursor = conn.cursor()
        
        try:
            cursor.execute(f"ALTER TABLE {old_name} RENAME TO {new_name}")
            conn.commit()
            self.logger.info(f"Renamed table: {old_name} -> {new_name}")
            return True
            
        except sqlite3.Error as e:
            self.logger.error(f"Error renaming table {old_name}: {e}")
            conn.rollback()
            return False
    
    def add_column(self, table_name: str, column_name: str, 
                  column_type: str, default_value: Optional[str] = None) -> bool:
        """Add a column to an existing table"""
        conn = self.connect()
        cursor = conn.cursor()
        
        try:
            sql = f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}"
            if default_value is not None:
                sql += f" DEFAULT {default_value}"
            
            cursor.execute(sql)
            conn.commit()
            self.logger.info(f"Added column {column_name} to table {table_name}")
            return True
            
        except sqlite3.Error as e:
            self.logger.error(f"Error adding column to {table_name}: {e}")
            conn.rollback()
            return False
    
    # Data Operations
    
    def execute_query(self, query: str, params: Optional[Tuple] = None) -> List[sqlite3.Row]:
        """Execute a SELECT query and return results"""
        conn = self.connect()
        cursor = conn.cursor()
        
        try:
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            
            return cursor.fetchall()
            
        except sqlite3.Error as e:
            self.logger.error(f"Error executing query: {e}")
            return []
    
    def execute_script(self, script: str) -> bool:
        """Execute multiple SQL statements"""
        conn = self.connect()
        cursor = conn.cursor()
        
        try:
            cursor.executescript(script)
            conn.commit()
            return True
            
        except sqlite3.Error as e:
            self.logger.error(f"Error executing script: {e}")
            conn.rollback()
            return False
    
    def insert_data(self, table_name: str, data: Union[Dict, List[Dict]]) -> bool:
        """
        Insert data into a table
        
        Args:
            table_name: Target table name
            data: Single dict or list of dicts with column: value pairs
        """
        conn = self.connect()
        cursor = conn.cursor()
        
        try:
            if isinstance(data, dict):
                data = [data]
            
            if not data:
                return True
            
            # Get column names from first record
            columns = list(data[0].keys())
            placeholders = ','.join(['?' for _ in columns])
            
            sql = f"INSERT INTO {table_name} ({','.join(columns)}) VALUES ({placeholders})"
            
            # Convert data to tuples
            values = [tuple(record[col] for col in columns) for record in data]
            
            cursor.executemany(sql, values)
            conn.commit()
            
            self.logger.info(f"Inserted {len(data)} rows into {table_name}")
            return True
            
        except sqlite3.Error as e:
            self.logger.error(f"Error inserting data into {table_name}: {e}")
            conn.rollback()
            return False
    
    def update_data(self, table_name: str, set_values: Dict[str, Any], 
                   where_condition: str, where_params: Optional[Tuple] = None) -> int:
        """
        Update data in a table
        
        Args:
            table_name: Target table name
            set_values: Dictionary of column: new_value pairs
            where_condition: WHERE clause (without WHERE keyword)
            where_params: Parameters for WHERE clause
            
        Returns:
            Number of rows updated
        """
        conn = self.connect()
        cursor = conn.cursor()
        
        try:
            set_clause = ','.join([f"{col} = ?" for col in set_values.keys()])
            sql = f"UPDATE {table_name} SET {set_clause} WHERE {where_condition}"
            
            params = list(set_values.values())
            if where_params:
                params.extend(where_params)
            
            cursor.execute(sql, params)
            conn.commit()
            
            rows_updated = cursor.rowcount
            self.logger.info(f"Updated {rows_updated} rows in {table_name}")
            return rows_updated
            
        except sqlite3.Error as e:
            self.logger.error(f"Error updating data in {table_name}: {e}")
            conn.rollback()
            return 0
    
    def delete_data(self, table_name: str, where_condition: str, 
                   where_params: Optional[Tuple] = None) -> int:
        """
        Delete data from a table
        
        Args:
            table_name: Target table name
            where_condition: WHERE clause (without WHERE keyword)
            where_params: Parameters for WHERE clause
            
        Returns:
            Number of rows deleted
        """
        conn = self.connect()
        cursor = conn.cursor()
        
        try:
            sql = f"DELETE FROM {table_name} WHERE {where_condition}"
            
            if where_params:
                cursor.execute(sql, where_params)
            else:
                cursor.execute(sql)
            
            conn.commit()
            
            rows_deleted = cursor.rowcount
            self.logger.info(f"Deleted {rows_deleted} rows from {table_name}")
            return rows_deleted
            
        except sqlite3.Error as e:
            self.logger.error(f"Error deleting data from {table_name}: {e}")
            conn.rollback()
            return 0
    
    # Import/Export Methods
    
    def export_to_csv(self, table_name: str, output_file: str, 
                     query: Optional[str] = None) -> bool:
        """
        Export table data to CSV file
        
        Args:
            table_name: Table to export (ignored if query provided)
            output_file: Output CSV file path
            query: Custom SQL query (optional)
        """
        conn = self.connect()
        cursor = conn.cursor()
        
        try:
            if query:
                cursor.execute(query)
            else:
                cursor.execute(f"SELECT * FROM {table_name}")
            
            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                # Get column names
                columns = [description[0] for description in cursor.description]
                writer = csv.DictWriter(csvfile, fieldnames=columns)
                writer.writeheader()
                
                # Write data
                for row in cursor.fetchall():
                    writer.writerow(dict(row))
            
            self.logger.info(f"Exported data to {output_file}")
            return True
            
        except (sqlite3.Error, IOError) as e:
            self.logger.error(f"Error exporting to CSV: {e}")
            return False
    
    def import_from_csv(self, table_name: str, csv_file: str, 
                       create_table: bool = False) -> bool:
        """
        Import data from CSV file
        
        Args:
            table_name: Target table name
            csv_file: CSV file path
            create_table: Whether to create table if it doesn't exist
        """
        try:
            with open(csv_file, 'r', encoding='utf-8') as file:
                reader = csv.DictReader(file)
                data = list(reader)
                
            if not data:
                self.logger.warning("No data found in CSV file")
                return True
            
            # Create table if requested
            if create_table:
                columns = []
                for col_name in data[0].keys():
                    columns.append({
                        'name': col_name,
                        'type': 'TEXT'  # Default to TEXT, can be refined
                    })
                self.create_table(table_name, columns)
            
            return self.insert_data(table_name, data)
            
        except (IOError, csv.Error) as e:
            self.logger.error(f"Error importing from CSV: {e}")
            return False
    
    def export_to_json(self, table_name: str, output_file: str, 
                      query: Optional[str] = None) -> bool:
        """Export table data to JSON file"""
        conn = self.connect()
        cursor = conn.cursor()
        
        try:
            if query:
                cursor.execute(query)
            else:
                cursor.execute(f"SELECT * FROM {table_name}")
            
            data = [dict(row) for row in cursor.fetchall()]
            
            with open(output_file, 'w', encoding='utf-8') as jsonfile:
                json.dump(data, jsonfile, indent=2, default=str)
            
            self.logger.info(f"Exported data to {output_file}")
            return True
            
        except (sqlite3.Error, IOError) as e:
            self.logger.error(f"Error exporting to JSON: {e}")
            return False
    
    def import_from_json(self, table_name: str, json_file: str, 
                        create_table: bool = False) -> bool:
        """Import data from JSON file"""
        try:
            with open(json_file, 'r', encoding='utf-8') as file:
                data = json.load(file)
                
            if not isinstance(data, list):
                data = [data]
                
            if not data:
                self.logger.warning("No data found in JSON file")
                return True
            
            # Create table if requested
            if create_table and data:
                columns = []
                for col_name in data[0].keys():
                    columns.append({
                        'name': col_name,
                        'type': 'TEXT'  # Default to TEXT
                    })
                self.create_table(table_name, columns)
            
            return self.insert_data(table_name, data)
            
        except (IOError, json.JSONDecodeError) as e:
            self.logger.error(f"Error importing from JSON: {e}")
            return False
    
    # Backup and Maintenance
    
    def backup_database(self, backup_path: str) -> bool:
        """Create a backup of the database"""
        try:
            if self.connection:
                # Use SQLite backup API for online backup
                backup_conn = sqlite3.connect(backup_path)
                self.connection.backup(backup_conn)
                backup_conn.close()
            else:
                # Simple file copy if no active connection
                shutil.copy2(self.database_path, backup_path)
            
            self.logger.info(f"Database backed up to {backup_path}")
            return True
            
        except (sqlite3.Error, IOError) as e:
            self.logger.error(f"Error backing up database: {e}")
            return False
    
    def vacuum_database(self) -> bool:
        """Vacuum database to reclaim space and optimize"""
        conn = self.connect()
        cursor = conn.cursor()
        
        try:
            cursor.execute("VACUUM")
            self.logger.info("Database vacuumed successfully")
            return True
            
        except sqlite3.Error as e:
            self.logger.error(f"Error vacuuming database: {e}")
            return False
    
    def analyze_database(self) -> bool:
        """Analyze database to update query optimizer statistics"""
        conn = self.connect()
        cursor = conn.cursor()
        
        try:
            cursor.execute("ANALYZE")
            conn.commit()
            self.logger.info("Database analyzed successfully")
            return True
            
        except sqlite3.Error as e:
            self.logger.error(f"Error analyzing database: {e}")
            return False
    
    def check_integrity(self) -> Dict[str, Any]:
        """Check database integrity"""
        conn = self.connect()
        cursor = conn.cursor()
        
        result = {
            'integrity_check': [],
            'foreign_key_check': [],
            'quick_check': []
        }
        
        try:
            # Integrity check
            cursor.execute("PRAGMA integrity_check")
            result['integrity_check'] = [row[0] for row in cursor.fetchall()]
            
            # Foreign key check
            cursor.execute("PRAGMA foreign_key_check")
            result['foreign_key_check'] = [dict(row) for row in cursor.fetchall()]
            
            # Quick check
            cursor.execute("PRAGMA quick_check")
            result['quick_check'] = [row[0] for row in cursor.fetchall()]
            
        except sqlite3.Error as e:
            self.logger.error(f"Error checking database integrity: {e}")
            
        return result
    
    # Index Management
    
    def create_index(self, index_name: str, table_name: str, 
                    columns: List[str], unique: bool = False) -> bool:
        """Create an index on specified columns"""
        conn = self.connect()
        cursor = conn.cursor()
        
        try:
            unique_clause = "UNIQUE " if unique else ""
            columns_str = ",".join(columns)
            sql = f"CREATE {unique_clause}INDEX {index_name} ON {table_name} ({columns_str})"
            
            cursor.execute(sql)
            conn.commit()
            
            self.logger.info(f"Created index: {index_name}")
            return True
            
        except sqlite3.Error as e:
            self.logger.error(f"Error creating index {index_name}: {e}")
            conn.rollback()
            return False
    
    def drop_index(self, index_name: str) -> bool:
        """Drop an index"""
        conn = self.connect()
        cursor = conn.cursor()
        
        try:
            cursor.execute(f"DROP INDEX IF EXISTS {index_name}")
            conn.commit()
            self.logger.info(f"Dropped index: {index_name}")
            return True
            
        except sqlite3.Error as e:
            self.logger.error(f"Error dropping index {index_name}: {e}")
            conn.rollback()
            return False


def setup_logging(level: str = "INFO"):
    """Setup logging configuration"""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )


def main():
    """Command line interface for SQLiteManager"""
    parser = argparse.ArgumentParser(description="SQLite Database Management Tool")
    parser.add_argument("database", help="SQLite database file path")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Info command
    info_parser = subparsers.add_parser("info", help="Show database information")
    
    # List tables command
    list_parser = subparsers.add_parser("tables", help="List all tables")
    
    # Table info command
    table_info_parser = subparsers.add_parser("table-info", help="Show table information")
    table_info_parser.add_argument("table", help="Table name")
    
    # Query command
    query_parser = subparsers.add_parser("query", help="Execute SQL query")
    query_parser.add_argument("sql", help="SQL query to execute")
    query_parser.add_argument("--output", help="Output file for results (JSON)")
    
    # Export command
    export_parser = subparsers.add_parser("export", help="Export table to file")
    export_parser.add_argument("table", help="Table name")
    export_parser.add_argument("output", help="Output file path")
    export_parser.add_argument("--format", choices=["csv", "json"], default="csv", help="Export format")
    export_parser.add_argument("--query", help="Custom SQL query instead of full table")
    
    # Import command
    import_parser = subparsers.add_parser("import", help="Import data from file")
    import_parser.add_argument("table", help="Target table name")
    import_parser.add_argument("input", help="Input file path")
    import_parser.add_argument("--format", choices=["csv", "json"], default="csv", help="Import format")
    import_parser.add_argument("--create-table", action="store_true", help="Create table if it doesn't exist")
    
    # Backup command
    backup_parser = subparsers.add_parser("backup", help="Backup database")
    backup_parser.add_argument("output", help="Backup file path")
    
    # Maintenance commands
    maintenance_parser = subparsers.add_parser("vacuum", help="Vacuum database")
    analyze_parser = subparsers.add_parser("analyze", help="Analyze database")
    integrity_parser = subparsers.add_parser("check", help="Check database integrity")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    setup_logging(args.log_level)
    
    # Initialize database manager
    with SQLiteManager(args.database) as db:
        
        if args.command == "info":
            info = db.get_database_info()
            print(f"Database: {info['database_path']}")
            print(f"Size: {info['file_size_mb']:.2f} MB")
            print(f"Tables: {len(info['tables'])}")
            print(f"Indexes: {len(info['indexes'])}")
            print(f"Views: {len(info['views'])}")
            print(f"Triggers: {len(info['triggers'])}")
            
        elif args.command == "tables":
            tables = db.list_tables()
            print(f"Tables ({len(tables)}):")
            for table in tables:
                print(f"  - {table}")
                
        elif args.command == "table-info":
            info = db.get_table_info(args.table)
            if not info['exists']:
                print(f"Table '{args.table}' does not exist")
                return
                
            print(f"Table: {info['name']}")
            print(f"Rows: {info['row_count']:,}")
            print(f"Columns ({len(info['columns'])}):")
            for col in info['columns']:
                pk = " (PK)" if col['primary_key'] else ""
                nn = " NOT NULL" if col['not_null'] else ""
                print(f"  - {col['name']}: {col['type']}{nn}{pk}")
                
        elif args.command == "query":
            results = db.execute_query(args.sql)
            if args.output:
                data = [dict(row) for row in results]
                with open(args.output, 'w') as f:
                    json.dump(data, f, indent=2, default=str)
                print(f"Results saved to {args.output}")
            else:
                for row in results:
                    print(dict(row))
                    
        elif args.command == "export":
            if args.format == "csv":
                success = db.export_to_csv(args.table, args.output, args.query)
            else:
                success = db.export_to_json(args.table, args.output, args.query)
            
            if success:
                print(f"Export completed: {args.output}")
            else:
                print("Export failed")
                
        elif args.command == "import":
            if args.format == "csv":
                success = db.import_from_csv(args.table, args.input, args.create_table)
            else:
                success = db.import_from_json(args.table, args.input, args.create_table)
            
            if success:
                print(f"Import completed")
            else:
                print("Import failed")
                
        elif args.command == "backup":
            success = db.backup_database(args.output)
            if success:
                print(f"Backup completed: {args.output}")
            else:
                print("Backup failed")
                
        elif args.command == "vacuum":
            success = db.vacuum_database()
            if success:
                print("Vacuum completed")
            else:
                print("Vacuum failed")
                
        elif args.command == "analyze":
            success = db.analyze_database()
            if success:
                print("Analyze completed")
            else:
                print("Analyze failed")
                
        elif args.command == "check":
            results = db.check_integrity()
            print("Integrity Check:")
            for item in results['integrity_check']:
                print(f"  {item}")
            
            if results['foreign_key_check']:
                print("Foreign Key Issues:")
                for item in results['foreign_key_check']:
                    print(f"  {item}")
            else:
                print("No foreign key issues found")


if __name__ == "__main__":
    main()
