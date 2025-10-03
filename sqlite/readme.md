
# SQLite Manager 🗂️

A robust **SQLite database management tool** for **Python 3** with both a **Python API** and a **CLI**.  
It provides schema management, data operations, import/export (CSV/JSON), backup, and maintenance utilities with proper logging and error handling.

---

## ✨ Features

- **Schema Management**: create, drop, rename tables; add columns; manage indexes  
- **Data Operations**: insert, update, delete, query data  
- **Import/Export**: CSV and JSON support  
- **Backup**: safe SQLite backup API or file copy  
- **Maintenance**: `VACUUM`, `ANALYZE`, integrity checks  
- **Information**: schema inspection, table info, row counts, foreign key info  
- **CLI Tool**: easy command-line interface  
- **Python API**: programmatic access to functions  

---

## 📦 Installation

Clone your repo and install dependencies (only built‑in modules required):

```bash
git clone https://github.com/yourname/sqlite-manager.git
cd sqlite-manager
python3 sqlite_manager.py --help
```

No external dependencies — pure Python 3.  

---

## 🚀 Command Line Usage

```bash
python sqlite_manager.py <database> <command> [options]
```

### Commands

- **Info**
  ```bash
  python sqlite_manager.py mydb.sqlite info
  ```
  Prints database info: file size, tables, indexes, schema.

- **List Tables**
  ```bash
  python sqlite_manager.py mydb.sqlite tables
  ```

- **Table Info**
  ```bash
  python sqlite_manager.py mydb.sqlite table-info users
  ```

- **Query**
  ```bash
  python sqlite_manager.py mydb.sqlite query "SELECT * FROM users LIMIT 5"
  python sqlite_manager.py mydb.sqlite query "SELECT * FROM users" --output results.json
  ```

- **Export**
  ```bash
  python sqlite_manager.py mydb.sqlite export users users.csv --format csv
  python sqlite_manager.py mydb.sqlite export users users.json --format json --query "SELECT id,name FROM users WHERE active=1"
  ```

- **Import**
  ```bash
  python sqlite_manager.py mydb.sqlite import users new_users.csv --format csv --create-table
  python sqlite_manager.py mydb.sqlite import users new_users.json --format json
  ```

- **Backup**
  ```bash
  python sqlite_manager.py mydb.sqlite backup backup.sqlite
  ```

- **Maintenance**
  ```bash
  python sqlite_manager.py mydb.sqlite vacuum
  python sqlite_manager.py mydb.sqlite analyze
  python sqlite_manager.py mydb.sqlite check
  ```

---

## 🐍 Programmatic Usage

```python
from sqlite_manager import SQLiteManager

with SQLiteManager("example.db") as db:
    # Create table
    db.create_table("users", [
        {"name": "id", "type": "INTEGER", "constraints": "PRIMARY KEY"},
        {"name": "name", "type": "TEXT", "constraints": "NOT NULL"},
        {"name": "email", "type": "TEXT", "constraints": "UNIQUE"}
    ])
    
    # Insert data
    db.insert_data("users", {"name": "Alice", "email": "alice@example.com"})
    
    # Query
    result = db.execute_query("SELECT * FROM users WHERE name=?", ("Alice",))
    for row in result:
        print(dict(row))
    
    # Export
    db.export_to_csv("users", "users.csv")

    # Backup
    db.backup_database("backup.db")
```

---

## ⚙️ Logging

By default logging is set to `INFO`. You can enable more detailed logs:

```bash
python sqlite_manager.py mydb.sqlite info --log-level DEBUG
```

---

## 🧪 Testing

You can quickly test functionality using the included script:

```bash
# Create a new db and add table
python sqlite_manager.py test.db info
python sqlite_manager.py test.db tables
```

---

## 📝 License

MIT License — feel free to use and modify.


##
##
