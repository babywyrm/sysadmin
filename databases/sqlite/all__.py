#!/usr/bin/env python3
"""
Robust SQLite Database Management Script ..(condensed)..
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
    """Comprehensive SQLite database management"""
    
    def __init__(self, db_path: str, timeout: float = 30.0):
        self.db_path = Path(db_path)
        self.timeout = timeout
        self.conn: Optional[sqlite3.Connection] = None
        self.logger = logging.getLogger(__name__)
        
    def connect(self) -> sqlite3.Connection:
        if not self.conn:
            self.conn = sqlite3.connect(str(self.db_path), timeout=self.timeout, check_same_thread=False)
            self.conn.execute("PRAGMA foreign_keys = ON")
            self.conn.row_factory = sqlite3.Row
        return self.conn
    
    def disconnect(self) -> None:
        if self.conn:
            self.conn.close()
            self.conn = None
    
    def __enter__(self): return self
    def __exit__(self, *args): self.disconnect()
    
    def _execute(self, query: str, params: Optional[Tuple] = None, fetch: str = None) -> Any:
        """Execute query with error handling"""
        try:
            cursor = self.connect().cursor()
            cursor.execute(query, params or ())
            if fetch == 'all': return cursor.fetchall()
            if fetch == 'one': return cursor.fetchone()
            self.conn.commit()
            return cursor.rowcount
        except sqlite3.Error as e:
            self.logger.error(f"SQL error: {e}")
            if self.conn: self.conn.rollback()
            return [] if fetch else 0
    
    def get_database_info(self) -> Dict[str, Any]:
        """Get comprehensive database information"""
        info = {
            'database_path': str(self.db_path),
            'file_size_mb': self.db_path.stat().st_size / (1024**2) if self.db_path.exists() else 0,
            'page_count': self._execute("PRAGMA page_count", fetch='one')[0],
            'page_size': self._execute("PRAGMA page_size", fetch='one')[0],
            'schema_version': self._execute("PRAGMA schema_version", fetch='one')[0],
            'user_version': self._execute("PRAGMA user_version", fetch='one')[0],
        }
        
        # Get schema objects
        objects = self._execute("SELECT name, type, sql FROM sqlite_master WHERE type IN ('table', 'index', 'trigger', 'view') ORDER BY type, name", fetch='all')
        for obj_type in ['tables', 'indexes', 'triggers', 'views']:
            info[obj_type] = [{'name': row['name'], 'sql': row['sql']} 
                             for row in objects if row['type'] == obj_type.rstrip('s')]
        
        return info
    
    def get_table_info(self, table: str) -> Dict[str, Any]:
        """Get detailed table information"""
        if not self._execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", (table,), 'one')[0]:
            return {'name': table, 'exists': False}
        
        return {
            'name': table,
            'exists': True,
            'columns': [dict(row) for row in self._execute(f"PRAGMA table_info({table})", fetch='all')],
            'indexes': [dict(row) for row in self._execute(f"PRAGMA index_list({table})", fetch='all')],
            'foreign_keys': [dict(row) for row in self._execute(f"PRAGMA foreign_key_list({table})", fetch='all')],
            'row_count': self._execute(f"SELECT COUNT(*) FROM {table}", fetch='one')[0]
        }
    
    def list_tables(self) -> List[str]:
        """Get all table names"""
        return [row['name'] for row in self._execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name", 
            fetch='all'
        )]
    
    def create_table(self, table: str, columns: List[Dict[str, str]], constraints: Optional[List[str]] = None) -> bool:
        """Create table with columns and constraints"""
        col_defs = [f"{col['name']} {col['type']} {col.get('constraints', '')}" for col in columns]
        if constraints: col_defs.extend(constraints)
        return bool(self._execute(f"CREATE TABLE {table} ({', '.join(col_defs)})"))
    
    def drop_table(self, table: str) -> bool:
        return bool(self._execute(f"DROP TABLE IF EXISTS {table}"))
    
    def rename_table(self, old: str, new: str) -> bool:
        return bool(self._execute(f"ALTER TABLE {old} RENAME TO {new}"))
    
    def add_column(self, table: str, name: str, col_type: str, default: Optional[str] = None) -> bool:
        sql = f"ALTER TABLE {table} ADD COLUMN {name} {col_type}"
        if default: sql += f" DEFAULT {default}"
        return bool(self._execute(sql))
    
    def execute_query(self, query: str, params: Optional[Tuple] = None) -> List[sqlite3.Row]:
        return self._execute(query, params, 'all')
    
    def execute_script(self, script: str) -> bool:
        try:
            self.connect().executescript(script)
            self.conn.commit()
            return True
        except sqlite3.Error as e:
            self.logger.error(f"Script error: {e}")
            if self.conn: self.conn.rollback()
            return False
    
    def insert_data(self, table: str, data: Union[Dict, List[Dict]]) -> bool:
        if isinstance(data, dict): data = [data]
        if not data: return True
        
        columns = list(data[0].keys())
        placeholders = ','.join(['?' for _ in columns])
        values = [tuple(record[col] for col in columns) for record in data]
        
        try:
            cursor = self.connect().cursor()
            cursor.executemany(f"INSERT INTO {table} ({','.join(columns)}) VALUES ({placeholders})", values)
            self.conn.commit()
            return True
        except sqlite3.Error as e:
            self.logger.error(f"Insert error: {e}")
            if self.conn: self.conn.rollback()
            return False
    
    def update_data(self, table: str, set_values: Dict[str, Any], where: str, where_params: Optional[Tuple] = None) -> int:
        set_clause = ','.join([f"{col} = ?" for col in set_values.keys()])
        params = list(set_values.values()) + (list(where_params) if where_params else [])
        return self._execute(f"UPDATE {table} SET {set_clause} WHERE {where}", tuple(params))
    
    def delete_data(self, table: str, where: str, where_params: Optional[Tuple] = None) -> int:
        return self._execute(f"DELETE FROM {table} WHERE {where}", where_params)
    
    def export_to_csv(self, table: str, output: str, query: Optional[str] = None) -> bool:
        try:
            rows = self.execute_query(query or f"SELECT * FROM {table}")
            if not rows: return True
            
            with open(output, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=[col[0] for col in rows[0].keys()])
                writer.writeheader()
                writer.writerows([dict(row) for row in rows])
            return True
        except (IOError, sqlite3.Error) as e:
            self.logger.error(f"CSV export error: {e}")
            return False
    
    def import_from_csv(self, table: str, csv_file: str, create_table: bool = False) -> bool:
        try:
            with open(csv_file, 'r', encoding='utf-8') as f:
                data = list(csv.DictReader(f))
            
            if create_table and data:
                columns = [{'name': col, 'type': 'TEXT'} for col in data[0].keys()]
                self.create_table(table, columns)
            
            return self.insert_data(table, data)
        except (IOError, csv.Error) as e:
            self.logger.error(f"CSV import error: {e}")
            return False
    
    def export_to_json(self, table: str, output: str, query: Optional[str] = None) -> bool:
        try:
            rows = self.execute_query(query or f"SELECT * FROM {table}")
            data = [dict(row) for row in rows]
            with open(output, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str)
            return True
        except (IOError, sqlite3.Error) as e:
            self.logger.error(f"JSON export error: {e}")
            return False
    
    def import_from_json(self, table: str, json_file: str, create_table: bool = False) -> bool:
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            if not isinstance(data, list): data = [data]
            if create_table and data:
                columns = [{'name': col, 'type': 'TEXT'} for col in data[0].keys()]
                self.create_table(table, columns)
            
            return self.insert_data(table, data)
        except (IOError, json.JSONDecodeError) as e:
            self.logger.error(f"JSON import error: {e}")
            return False
    
    def backup_database(self, backup_path: str) -> bool:
        try:
            if self.conn:
                backup_conn = sqlite3.connect(backup_path)
                self.conn.backup(backup_conn)
                backup_conn.close()
            else:
                shutil.copy2(self.db_path, backup_path)
            return True
        except (sqlite3.Error, IOError) as e:
            self.logger.error(f"Backup error: {e}")
            return False
    
    def vacuum_database(self) -> bool:
        return bool(self._execute("VACUUM"))
    
    def analyze_database(self) -> bool:
        return bool(self._execute("ANALYZE"))
    
    def check_integrity(self) -> Dict[str, List]:
        return {
            'integrity_check': [row[0] for row in self._execute("PRAGMA integrity_check", fetch='all')],
            'foreign_key_check': [dict(row) for row in self._execute("PRAGMA foreign_key_check", fetch='all')],
            'quick_check': [row[0] for row in self._execute("PRAGMA quick_check", fetch='all')]
        }
    
    def create_index(self, name: str, table: str, columns: List[str], unique: bool = False) -> bool:
        unique_clause = "UNIQUE " if unique else ""
        return bool(self._execute(f"CREATE {unique_clause}INDEX {name} ON {table} ({','.join(columns)})"))
    
    def drop_index(self, name: str) -> bool:
        return bool(self._execute(f"DROP INDEX IF EXISTS {name}"))


def setup_logging(level: str = "INFO"):
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler(sys.stdout)]
    )


def main():
    parser = argparse.ArgumentParser(description="SQLite Database Management Tool")
    parser.add_argument("database", help="SQLite database file path")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    
    sub = parser.add_subparsers(dest="command", help="Available commands")
    
    sub.add_parser("info", help="Show database information")
    sub.add_parser("tables", help="List all tables")
    
    table_info = sub.add_parser("table-info", help="Show table information")
    table_info.add_argument("table", help="Table name")
    
    query_cmd = sub.add_parser("query", help="Execute SQL query")
    query_cmd.add_argument("sql", help="SQL query")
    query_cmd.add_argument("--output", help="Output file (JSON)")
    
    export_cmd = sub.add_parser("export", help="Export table")
    export_cmd.add_argument("table", help="Table name")
    export_cmd.add_argument("output", help="Output file")
    export_cmd.add_argument("--format", choices=["csv", "json"], default="csv")
    export_cmd.add_argument("--query", help="Custom query")
    
    import_cmd = sub.add_parser("import", help="Import data")
    import_cmd.add_argument("table", help="Table name")
    import_cmd.add_argument("input", help="Input file")
    import_cmd.add_argument("--format", choices=["csv", "json"], default="csv")
    import_cmd.add_argument("--create-table", action="store_true")
    
    backup_cmd = sub.add_parser("backup", help="Backup database")
    backup_cmd.add_argument("output", help="Backup file")
    
    sub.add_parser("vacuum", help="Vacuum database")
    sub.add_parser("analyze", help="Analyze database")
    sub.add_parser("check", help="Check integrity")
    
    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return
    
    setup_logging(args.log_level)
    
    with SQLiteManager(args.database) as db:
        if args.command == "info":
            info = db.get_database_info()
            print(f"Database: {info['database_path']}")
            print(f"Size: {info['file_size_mb']:.2f} MB")
            print(f"Tables: {len(info['tables'])}, Indexes: {len(info['indexes'])}")
            
        elif args.command == "tables":
            tables = db.list_tables()
            print(f"Tables ({len(tables)}):")
            for table in tables: print(f"  - {table}")
                
        elif args.command == "table-info":
            info = db.get_table_info(args.table)
            if not info['exists']:
                print(f"Table '{args.table}' does not exist")
                return
            print(f"Table: {info['name']}, Rows: {info['row_count']:,}")
            print(f"Columns ({len(info['columns'])}):")
            for col in info['columns']:
                flags = []
                if col['pk']: flags.append("PK")
                if col['notnull']: flags.append("NOT NULL")
                flag_str = f" ({', '.join(flags)})" if flags else ""
                print(f"  - {col['name']}: {col['type']}{flag_str}")
                
        elif args.command == "query":
            results = db.execute_query(args.sql)
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump([dict(row) for row in results], f, indent=2, default=str)
                print(f"Results saved to {args.output}")
            else:
                for row in results: print(dict(row))
                    
        elif args.command == "export":
            func = db.export_to_csv if args.format == "csv" else db.export_to_json
            success = func(args.table, args.output, args.query)
            print("Export completed" if success else "Export failed")
                
        elif args.command == "import":
            func = db.import_from_csv if args.format == "csv" else db.import_from_json
            success = func(args.table, args.input, args.create_table)
            print("Import completed" if success else "Import failed")
                
        elif args.command == "backup":
            success = db.backup_database(args.output)
            print(f"Backup {'completed' if success else 'failed'}")
                
        elif args.command in ["vacuum", "analyze"]:
            func = db.vacuum_database if args.command == "vacuum" else db.analyze_database
            success = func()
            print(f"{args.command.title()} {'completed' if success else 'failed'}")
                
        elif args.command == "check":
            results = db.check_integrity()
            print("Integrity Check:")
            for item in results['integrity_check']: print(f"  {item}")
            if results['foreign_key_check']:
                print("Foreign Key Issues:")
                for item in results['foreign_key_check']: print(f"  {item}")
            else:
                print("No foreign key issues found")


if __name__ == "__main__":
    main()
