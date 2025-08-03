
# Replacing Bash Scripting with Python: A Modern Guide

A comprehensive guide for transitioning from Bash scripting to Python for system administration and automation tasks.

## Table of Contents

- [Introduction](#introduction)
- [Why Replace Bash?](#why-replace-bash)
- [Why Python?](#why-python)
- [Prerequisites](#prerequisites)
- [File Operations](#file-operations)
- [Command-Line Interfaces](#command-line-interfaces)
- [Filesystem Operations](#filesystem-operations)
- [Text Processing and Pattern Matching](#text-processing-and-pattern-matching)
- [Process Management](#process-management)
- [System Integration](#system-integration)
- [Best Practices](#best-practices)

## Introduction

The Unix shell remains one of the most powerful tools for system administration, excelling at process orchestration and I/O handling. However, when scripts require complex data manipulation, control structures, or error handling, Python offers significant advantages in maintainability, readability, and safety.

This guide demonstrates how to accomplish common Bash scripting tasks using Python, focusing on practical examples and modern best practices.

## Why Replace Bash?

### Limitations of Bash for Complex Scripts

**Text-based Everything**: Bash treats identifiers, values, and code as text, leading to:
- Injection vulnerabilities by default
- Complex quoting requirements
- Difficult debugging and maintenance

**Example of Bash complexity:**
```bash
# Unsafe - prone to word splitting and injection
echo $foo

# Safe but verbose
echo "$foo"

# Array iteration requires special syntax
for item in "${my_array[@]}"; do
    echo "$item"
done
```

**Equivalent Python code:**
```python
# Clear, safe, and intuitive
print(foo)

# Simple iteration
for item in my_array:
    print(item)
```

### When Bash Is Appropriate

Bash excels at:
- Process orchestration and pipelines
- Simple file operations
- System setup and configuration
- Short scripts (< 50 lines) with minimal logic

## Why Python?

Python offers several advantages for administrative scripting:

- **Safety**: No injection vulnerabilities by default
- **Readability**: Clear, consistent syntax
- **Rich ecosystem**: Extensive standard library and third-party packages
- **Cross-platform**: Works consistently across Unix-like systems
- **Maintainability**: Easier to debug, test, and extend

### Alternative Languages

Other suitable languages include:
- **Perl**: Excellent for text processing, mature ecosystem
- **Ruby**: Clean syntax, good for automation
- **Go**: Fast compilation, good for system tools
- **Rust**: Memory safety, performance-critical applications

## Prerequisites

This guide assumes:
- Python 3.8 or higher (3.10+ recommended)
- Basic Python knowledge (variables, functions, control structures)
- Familiarity with common Unix tools

### Learning Resources

- [Official Python Tutorial](https://docs.python.org/3/tutorial/)
- [Real Python](https://realpython.com/)
- [Python Documentation](https://docs.python.org/3/)

## File Operations

### Reading Files

**Bash:**
```bash
while IFS= read -r line; do
    echo "$line"
done < file.txt
```

**Python:**
```python
from pathlib import Path

# Modern approach using pathlib
content = Path('file.txt').read_text()
print(content)

# Line-by-line processing
for line in Path('file.txt').open():
    print(line.rstrip())

# Context manager for explicit control
with open('file.txt') as f:
    for line in f:
        process_line(line.rstrip())
```

### Writing Files

**Bash:**
```bash
echo "Hello, World!" > file.txt
echo "Another line" >> file.txt
```

**Python:**
```python
from pathlib import Path

# Write entire content
Path('file.txt').write_text("Hello, World!\n")

# Append to file
with open('file.txt', 'a') as f:
    f.write("Another line\n")

# Multiple lines
lines = ['line1', 'line2', 'line3']
Path('file.txt').write_text('\n'.join(lines) + '\n')
```

### File Information and Testing

**Bash:**
```bash
if [[ -f "$file" ]]; then
    echo "File exists"
fi

if [[ -d "$dir" ]]; then
    echo "Directory exists"
fi
```

**Python:**
```python
from pathlib import Path

file_path = Path('myfile.txt')
dir_path = Path('mydir')

# File existence and type checking
if file_path.is_file():
    print("File exists")

if dir_path.is_dir():
    print("Directory exists")

# Get file statistics
stat = file_path.stat()
print(f"Size: {stat.st_size} bytes")
print(f"Modified: {stat.st_mtime}")

# Permission checking
if file_path.exists() and file_path.stat().st_mode & 0o400:
    print("File is readable")
```

## Command-Line Interfaces

### Working with stdin/stdout/stderr

**Python stdin processing:**
```python
import sys

# Read from stdin line by line
for line in sys.stdin:
    processed = line.strip().upper()
    print(processed)

# Read all stdin at once
content = sys.stdin.read()
print(f"Received {len(content)} characters")
```

### Command-line Arguments

**Modern argument parsing:**
```python
import argparse
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(
        description='Process files with options'
    )
    parser.add_argument('files', nargs='+', type=Path,
                       help='Files to process')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('-o', '--output', type=Path,
                       help='Output file')
    
    args = parser.parse_args()
    
    for file_path in args.files:
        if args.verbose:
            print(f"Processing {file_path}")
        
        # Process file
        content = file_path.read_text()
        result = process_content(content)
        
        if args.output:
            args.output.write_text(result)
        else:
            print(result)

if __name__ == '__main__':
    main()
```

### Environment Variables and Configuration

**Environment variables:**
```python
import os
from pathlib import Path

# Access environment variables
home = Path(os.environ['HOME'])
path = os.environ.get('PATH', '').split(':')

# Set environment variables
os.environ['MY_VAR'] = 'value'
```

**Configuration files:**
```python
import json
import tomllib  # Python 3.11+
from pathlib import Path

# JSON configuration
config = json.loads(Path('config.json').read_text())

# TOML configuration (modern alternative)
with open('config.toml', 'rb') as f:
    config = tomllib.load(f)

# Environment-based configuration
class Config:
    def __init__(self):
        self.debug = os.getenv('DEBUG', 'false').lower() == 'true'
        self.database_url = os.getenv('DATABASE_URL', 'sqlite:///default.db')
        self.log_level = os.getenv('LOG_LEVEL', 'INFO')
```

## Filesystem Operations

### Path Operations with pathlib

**Modern path handling:**
```python
from pathlib import Path

# Create paths
current_dir = Path('.')
home = Path.home()
temp_dir = Path('/tmp')

# Path manipulation
file_path = current_dir / 'subdir' / 'file.txt'
parent = file_path.parent
filename = file_path.name
stem = file_path.stem  # filename without extension
suffix = file_path.suffix  # file extension

# Absolute paths
abs_path = file_path.resolve()

# Path components
parts = abs_path.parts
print(f"Root: {parts[0]}")
print(f"Directories: {parts[1:-1]}")
print(f"Filename: {parts[-1]}")
```

### Directory Operations

**Directory traversal and manipulation:**
```python
from pathlib import Path

# List directory contents
for item in Path('.').iterdir():
    if item.is_file():
        print(f"File: {item}")
    elif item.is_dir():
        print(f"Directory: {item}")

# Recursive file finding (modern glob)
python_files = list(Path('.').rglob('*.py'))
config_files = list(Path('.').glob('**/*.{json,yaml,toml}'))

# Create directories
new_dir = Path('new/nested/directory')
new_dir.mkdir(parents=True, exist_ok=True)

# Directory statistics
total_size = sum(f.stat().st_size for f in Path('.').rglob('*') if f.is_file())
print(f"Total size: {total_size} bytes")
```

### File Operations with shutil

**Advanced file operations:**
```python
import shutil
from pathlib import Path

# Copy operations
shutil.copy2('source.txt', 'destination.txt')  # Copy with metadata
shutil.copytree('source_dir', 'dest_dir')      # Recursive copy

# Move operations
shutil.move('old_location', 'new_location')

# Archive operations
shutil.make_archive('backup', 'gztar', 'directory_to_backup')
shutil.unpack_archive('backup.tar.gz', 'extract_to')

# System information
usage = shutil.disk_usage('.')
print(f"Free space: {usage.free / 1024**3:.2f} GB")

# Find executables
git_path = shutil.which('git')
if git_path:
    print(f"Git found at: {git_path}")
```

## Text Processing and Pattern Matching

### String Operations

**Basic string processing:**
```python
import re
from pathlib import Path

def process_log_file(log_path: Path):
    """Process log file for errors and warnings."""
    lines = log_path.read_text().splitlines()
    
    errors = []
    warnings = []
    
    for line_num, line in enumerate(lines, 1):
        line_lower = line.lower()
        
        if 'error' in line_lower:
            errors.append((line_num, line))
        elif 'warning' in line_lower:
            warnings.append((line_num, line))
    
    return {
        'errors': errors,
        'warnings': warnings,
        'total_lines': len(lines)
    }

# Usage
results = process_log_file(Path('/var/log/application.log'))
print(f"Found {len(results['errors'])} errors")
```

### Regular Expressions

**Pattern matching and replacement:**
```python
import re
from typing import Iterator

def extract_ip_addresses(text: str) -> list[str]:
    """Extract IP addresses from text."""
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    return re.findall(ip_pattern, text)

def clean_phone_numbers(text: str) -> str:
    """Standardize phone number format."""
    # Match various phone number formats
    pattern = r'(\(?\d{3}\)?[-.\s]?)(\d{3})[-.\s]?(\d{4})'
    replacement = r'(\1) \2-\3'
    return re.sub(pattern, replacement, text)

def filter_lines(lines: Iterator[str], pattern: str) -> Iterator[str]:
    """Filter lines matching regex pattern."""
    compiled_pattern = re.compile(pattern)
    for line in lines:
        if compiled_pattern.search(line):
            yield line

# Example usage
log_text = Path('access.log').read_text()
ip_addresses = extract_ip_addresses(log_text)
print(f"Found IP addresses: {ip_addresses}")

# Process large files efficiently
with open('large_file.txt') as f:
    error_lines = list(filter_lines(f, r'ERROR|CRITICAL'))
```

### Text Transformation

**Advanced text processing:**
```python
import csv
from io import StringIO
from collections import Counter

def analyze_csv_data(csv_path: Path) -> dict:
    """Analyze CSV data and return statistics."""
    with csv_path.open() as f:
        reader = csv.DictReader(f)
        data = list(reader)
    
    # Count occurrences of values in specific columns
    status_counts = Counter(row['status'] for row in data)
    
    # Calculate numerical statistics
    if 'amount' in data[0]:
        amounts = [float(row['amount']) for row in data if row['amount']]
        avg_amount = sum(amounts) / len(amounts)
    else:
        avg_amount = None
    
    return {
        'total_rows': len(data),
        'status_distribution': dict(status_counts),
        'average_amount': avg_amount
    }

def transform_data(input_path: Path, output_path: Path):
    """Transform CSV data with custom logic."""
    with input_path.open() as infile, output_path.open('w') as outfile:
        reader = csv.DictReader(infile)
        fieldnames = reader.fieldnames + ['processed_at']
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for row in reader:
            # Transform data
            row['processed_at'] = datetime.now().isoformat()
            if 'email' in row:
                row['email'] = row['email'].lower()
            
            writer.writerow(row)
```

## Process Management

### Running External Commands

**Modern subprocess usage:**
```python
import subprocess as sp
from pathlib import Path
from typing import Optional

def run_command(
    cmd: list[str], 
    check: bool = True,
    capture_output: bool = False,
    text: bool = True,
    cwd: Optional[Path] = None
) -> sp.CompletedProcess:
    """Run external command with sensible defaults."""
    try:
        result = sp.run(
            cmd,
            check=check,
            capture_output=capture_output,
            text=text,
            cwd=cwd
        )
        return result
    except sp.CalledProcessError as e:
        print(f"Command failed: {' '.join(cmd)}")
        print(f"Exit code: {e.returncode}")
        if e.stdout:
            print(f"Stdout: {e.stdout}")
        if e.stderr:
            print(f"Stderr: {e.stderr}")
        raise

# Examples
def git_status(repo_path: Path) -> str:
    """Get git status for a repository."""
    result = run_command(
        ['git', 'status', '--porcelain'],
        capture_output=True,
        cwd=repo_path
    )
    return result.stdout

def compress_directory(source: Path, output: Path):
    """Compress directory using tar."""
    run_command([
        'tar', 'czf', str(output), '-C', str(source.parent), source.name
    ])

def rsync_backup(source: Path, destination: Path, dry_run: bool = False):
    """Backup using rsync."""
    cmd = ['rsync', '-av', '--delete']
    if dry_run:
        cmd.append('--dry-run')
    cmd.extend([str(source) + '/', str(destination)])
    
    run_command(cmd)
```

### Process Monitoring and Background Tasks

**Advanced process management:**
```python
import subprocess as sp
import threading
import time
from pathlib import Path

class ProcessManager:
    """Manage background processes."""
    
    def __init__(self):
        self.processes = {}
    
    def start_background(self, name: str, cmd: list[str]) -> sp.Popen:
        """Start a background process."""
        proc = sp.Popen(
            cmd,
            stdout=sp.PIPE,
            stderr=sp.PIPE,
            text=True
        )
        self.processes[name] = proc
        return proc
    
    def monitor_process(self, name: str, callback=None):
        """Monitor process output in a separate thread."""
        if name not in self.processes:
            raise ValueError(f"Process {name} not found")
        
        proc = self.processes[name]
        
        def monitor():
            for line in proc.stdout:
                if callback:
                    callback(line.rstrip())
                else:
                    print(f"[{name}] {line.rstrip()}")
        
        thread = threading.Thread(target=monitor, daemon=True)
        thread.start()
        return thread
    
    def wait_for_completion(self, name: str, timeout: Optional[float] = None):
        """Wait for process to complete."""
        if name not in self.processes:
            raise ValueError(f"Process {name} not found")
        
        proc = self.processes[name]
        try:
            proc.wait(timeout=timeout)
        except sp.TimeoutExpired:
            proc.kill()
            proc.wait()
            raise
    
    def cleanup(self):
        """Clean up all processes."""
        for name, proc in self.processes.items():
            if proc.poll() is None:  # Still running
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except sp.TimeoutExpired:
                    proc.kill()
                    proc.wait()

# Usage example
def deploy_application():
    """Example deployment with multiple processes."""
    pm = ProcessManager()
    
    try:
        # Start build process
        pm.start_background('build', ['npm', 'run', 'build'])
        pm.wait_for_completion('build', timeout=300)
        
        # Start tests
        pm.start_background('test', ['npm', 'test'])
        pm.wait_for_completion('test', timeout=120)
        
        # Deploy
        run_command(['kubectl', 'apply', '-f', 'deployment.yaml'])
        
    finally:
        pm.cleanup()
```

## System Integration

### Logging and Error Handling

**Professional logging setup:**
```python
import logging
import sys
from pathlib import Path
from typing import Optional

def setup_logging(
    level: str = 'INFO',
    log_file: Optional[Path] = None,
    format_string: Optional[str] = None
) -> logging.Logger:
    """Set up logging with console and optional file output."""
    
    if format_string is None:
        format_string = (
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    # Create logger
    logger = logging.getLogger()
    logger.setLevel(getattr(logging, level.upper()))
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(logging.Formatter(format_string))
    logger.addHandler(console_handler)
    
    # File handler (optional)
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter(format_string))
        logger.addHandler(file_handler)
    
    return logger

# Usage in scripts
def main():
    logger = setup_logging(
        level='INFO',
        log_file=Path('logs/application.log')
    )
    
    try:
        logger.info("Starting application")
        # Your application logic here
        
    except Exception as e:
        logger.error(f"Application failed: {e}", exc_info=True)
        sys.exit(1)
    else:
        logger.info("Application completed successfully")
```

### Configuration Management

**Environment-aware configuration:**
```python
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

@dataclass
class AppConfig:
    """Application configuration."""
    
    # Database settings
    database_url: str = 'sqlite:///app.db'
    database_pool_size: int = 10
    
    # Logging settings
    log_level: str = 'INFO'
    log_file: Optional[Path] = None
    
    # Feature flags
    debug_mode: bool = False
    enable_metrics: bool = True
    
    # External services
    api_base_url: str = 'https://api.example.com'
    api_timeout: int = 30
    
    @classmethod
    def from_environment(cls) -> 'AppConfig':
        """Load configuration from environment variables."""
        return cls(
            database_url=os.getenv('DATABASE_URL', cls.database_url),
            database_pool_size=int(os.getenv('DB_POOL_SIZE', cls.database_pool_size)),
            log_level=os.getenv('LOG_LEVEL', cls.log_level),
            log_file=Path(f) if (f := os.getenv('LOG_FILE')) else None,
            debug_mode=os.getenv('DEBUG', 'false').lower() == 'true',
            enable_metrics=os.getenv('ENABLE_METRICS', 'true').lower() == 'true',
            api_base_url=os.getenv('API_BASE_URL', cls.api_base_url),
            api_timeout=int(os.getenv('API_TIMEOUT', cls.api_timeout)),
        )
    
    @classmethod
    def from_file(cls, config_path: Path) -> 'AppConfig':
        """Load configuration from TOML file."""
        import tomllib
        
        with config_path.open('rb') as f:
            data = tomllib.load(f)
        
        # Map TOML structure to config fields
        return cls(
            database_url=data.get('database', {}).get('url', cls.database_url),
            database_pool_size=data.get('database', {}).get('pool_size', cls.database_pool_size),
            log_level=data.get('logging', {}).get('level', cls.log_level),
            debug_mode=data.get('debug', cls.debug_mode),
            # ... map other fields
        )

# Usage
config = AppConfig.from_environment()
logger = setup_logging(level=config.log_level, log_file=config.log_file)
```

## Best Practices

### Error Handling and Robustness

**Comprehensive error handling:**
```python
import sys
import signal
from contextlib import contextmanager
from pathlib import Path

class ScriptError(Exception):
    """Base exception for script errors."""
    pass

class ValidationError(ScriptError):
    """Raised when input validation fails."""
    pass

@contextmanager
def error_handling():
    """Context manager for graceful error handling."""
    try:
        yield
    except KeyboardInterrupt:
        print("\nOperation cancelled by user", file=sys.stderr)
        sys.exit(130)  # Standard exit code for SIGINT
    except ValidationError as e:
        print(f"Validation error: {e}", file=sys.stderr)
        sys.exit(2)
    except ScriptError as e:
        print(f"Script error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)

def validate_inputs(file_paths: list[Path]) -> None:
    """Validate input files exist and are readable."""
    for path in file_paths:
        if not path.exists():
            raise ValidationError(f"File not found: {path}")
        if not path.is_file():
            raise ValidationError(f"Not a file: {path}")
        if not os.access(path, os.R_OK):
            raise ValidationError(f"File not readable: {path}")

# Signal handling for cleanup
def setup_signal_handlers(cleanup_func):
    """Set up signal handlers for graceful shutdown."""
    def signal_handler(signum, frame):
        print(f"\nReceived signal {signum}, cleaning up...")
        cleanup_func()
        sys.exit(0)
    
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
```

### Performance and Memory Management

**Efficient data processing:**
```python
import mmap
from itertools import islice
from pathlib import Path

def process_large_file_efficiently(file_path: Path, chunk_size: int = 8192):
    """Process large files without loading everything into memory."""
    
    def process_chunk(lines):
        """Process a chunk of lines."""
        # Your processing logic here
        for line in lines:
            yield line.upper()
    
    with file_path.open() as f:
        while True:
            chunk = list(islice(f, chunk_size))
            if not chunk:
                break
            
            yield from process_chunk(chunk)

def memory_mapped_search(file_path: Path, pattern: bytes) -> list[int]:
    """Search for pattern in large file using memory mapping."""
    positions = []
    
    with file_path.open('rb') as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            pos = 0
            while True:
                pos = mm.find(pattern, pos)
                if pos == -1:
                    break
                positions.append(pos)
                pos += 1
    
    return positions

# Generator-based processing for memory efficiency
def process_files_generator(file_paths: list[Path]):
    """Process multiple files efficiently using generators."""
    for file_path in file_paths:
        with file_path.open() as f:
            for line_num, line in enumerate(f, 1):
                # Process line and yield result
                processed = line.strip()
                if processed:  # Skip empty lines
                    yield {
                        'file': file_path.name,
                        'line_number': line_num,
                        'content': processed
                    }
```

### Testing and Validation

**Testable script structure:**
```python
from pathlib import Path
from typing import Optional
import tempfile

def backup_files(
    source_paths: list[Path],
    backup_dir: Path,
    compress: bool = True,
    dry_run: bool = False
) -> dict:
    """
    Backup files to specified directory.
    
    Returns:
        Dictionary with backup results and statistics.
    """
    results = {
        'backed_up': [],
        'failed': [],
        'total_size': 0
    }
    
    # Ensure backup directory exists
    if not dry_run:
        backup_dir.mkdir(parents=True, exist_ok=True)
    
    for source_path in source_paths:
        try:
            if not source_path.exists():
                results['failed'].append(f"Not found: {source_path}")
                continue
            
            # Calculate backup path
            backup_path = backup_dir / source_path.name
            if compress:
                backup_path = backup_path.with_suffix(backup_path.suffix + '.gz')
            
            if dry_run:
                print(f"Would backup {source_path} -> {backup_path}")
            else:
                # Perform actual backup
                if compress:
                    import gzip
                    import shutil
                    
                    with source_path.open('rb') as src:
                        with gzip.open(backup_path, 'wb') as dst:
                            shutil.copyfileobj(src, dst)
                else:
                    shutil.copy2(source_path, backup_path)
            
            results['backed_up'].append(str(backup_path))
            results['total_size'] += source_path.stat().st_size
            
        except Exception as e:
            results['failed'].append(f"Error backing up {source_path}: {e}")
    
    return results

def main():
    """Main function for CLI usage."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Backup files')
    parser.add_argument('files', nargs='+', type=Path, help='Files to backup')
    parser.add_argument('-d', '--backup-dir', type=Path, required=True,
                       help='Backup directory')
    parser.add_argument('-c', '--compress', action='store_true',
                       help='Compress backups')
    parser.add_argument('-n', '--dry-run', action='store_true',
                       help='Show what would be done')
    
    args = parser.parse_args()
    
    with error_handling():
        validate_inputs(args.files)
        results = backup_files(
            args.files,
            args.backup_dir,
            compress=args.compress,
            dry_run=args.dry_run
        )
        
        print(f"Successfully backed up {len(results['backed_up'])} files")
        print(f"Total size: {results['total_size']} bytes")
        
        if results['failed']:
            print(f"Failed: {len(results['failed'])} files")
            for failure in results['failed']:
                print(f"  {failure}")

if __name__ == '__main__':
    main()
```

## Conclusion

Python provides a robust, maintainable alternative to complex Bash scripts while preserving the ability to integrate with Unix tools and workflows. Key advantages include:

- **Safety**: Elimination of injection vulnerabilities
- **Maintainability**: Clear syntax and structure
- **Testability**: Easy to unit test and debug
- **Extensibility**: Rich ecosystem of libraries
- **Cross-platform compatibility**: Works across different Unix-like systems

### When to Use Each Tool

**Use Bash for:**
- Simple process orchestration
- File operations and system setup
- Scripts under 50 lines with minimal logic
- Interactive command-line workflows

**Use Python for:**
- Data processing and manipulation
- Complex conditional logic
- Error handling and validation
- Scripts that need to scale or be maintained long-term
- Integration with APIs or databases

### Migration Strategy

1. **Start small**: Replace individual functions or components
2. **Maintain interfaces**: Ensure Python scripts work in existing pipelines
3. **Add proper error handling**: Take advantage of Python's exception system
4. **Include tests**: Validate functionality and prevent regressions
5. **Document thoroughly**: Make maintenance easier for future developers

This approach allows you to leverage the strengths of both tools while building more robust and maintainable automation solutions.

##
##

Epilogue: Choose the right tool for the job.
--------------------------------------------
One of the main criticism of this tutorial (I suspect from people who
haven't read it very well) is that it goes against the philosophy of
using the best tool for the job. My intention is not that people rewrite
all existing Bash in Python (though sometimes rewrites might be a net
gain), nor am I attempting to get people to entirely stop writing new
Bash scripts.

The tutorial has also been accused of being a "commercial for Python."
I would have thought the `Why Python?`_ section would show that this is
not the case, but if not, let me reiterate: Python is one of many
languages well suited to administrative scripting. The others also
provide a safer, clearer way to deal with data than the shell. My goal
is not to get people to use Python as much as it is to try to get people
to stop handling data in shell scripts.

The "founding fathers" of Unix had already recognized the fundamental
limitations of the Bourne shell for handling data and created AWK, a
complementary, string-centric data parsing language. Modern Bash, on the
other hand, has added a lot of data related features which make it
possible to do many of the things you might do in AWK directly in Bash.
Do not use them. They are ugly and difficult to get right. Use AWK
instead, or Perl or Python or whatever.

When to use Bash
++++++++++++++++
I do believe that for a program which deals primarily with starting
processes and connecting their inputs and outputs, as well as certain
kinds of file management tasks, the shell should still be the first
candidate. A good example might be setting up a server. I keep config
files for my shell environment in Git (like any sane person), and I
use ``sh`` for all the setup. That's fine. In fact, it's great. Running
some commands and symlinking files is a usecase that fits perfectly to
the strengths of the shell.

I also have shell scripts for automating certain parts of my build,
testing and publishing workflow for my programming, and I will probably
continue to use such scripts for a long time. (I also use Python for
some of that stuff. Depends on the nature of the task.)

Warning Signs
+++++++++++++
Many people have rule about the length of their Bash scripts. It is oft
repeated on the Internet that, "If your shell script gets to fifty lines,
rewrite in another language," or something similar. The number of lines
varies from 10 to 20 to 50 to 100. Among the Unix old guard, "another
language" is basically always Perl. I like Python because reasons, but
the important thing is that it's not Bash.

This kind of rule isn't too bad. Length isn't the problem, but length
*can* be a side-effect of complexity, and complexity is sort of the
arch-enemy of Bash. I look for the use of certain features to be an
indicator that it's time to consider a rewrite. (note that "rewrite" can
mean moving certain parts of the logic into another language while still
doing orchestration in Bash). These "warning signs are" listed in order
of more to less serious.

- If you ever need to type the characters ``IFS=``, rewrite immediately.
  You're on the highway to Hell.
- If data is being stored in Bash arrays, either refactor so the data
  can be streamed through pipelines or use a different language. As with
  ``IFS``, it means you're entering the wild world of the shell's string
  splitting rules. That's not the world for you.
- If you find yourself using braced parameter expansion syntax,
  ``${my_var}``, and anything is between those braces besides the name
  of your variable, it's a bad sign. For one, it means you might be
  using an array, and that's not good. If you're not using an array, it
  means you're using the shell's string manipulation capabilities. There
  are cases where this might be allowable (determining the basename of a
  file, for example), but the syntax for that kind of thing is very
  strange, and so many other languages supply better string manipulating
  tools. If you're doing batch file renaming, ``pathlib`` provides a
  much saner interface, in my opinion.
- Dealing with process output in a loop is not a great idea. If you HAVE
  to do it, the only right way is with ``while IFS= read -r line``.
  Don't listen to anyone who tells you differently, ever. Always try to
  refactor this case as a one-liner with AWK or Perl, or write a script
  in another language to process the data and call it from Bash.  If you
  have a loop like this, and you are starting any processes inside the
  loop, you will have major performance problems. This will eventually
  lead to refactoring with Bash built-ins. In the final stages, it
  results in madness and suicide.
- Bash functions, while occasionally useful, can be a sign of trouble.
  All the variables are global by default. It also means there is enough
  complexity that you can't do it with a completely linear control flow.
  That's also not a good sign for Bash. A few Bash functions might be
  alright, but it's a warning sign.
- Conditional logic, while it can definitely be useful, is also a sign
  of increasing complexity. As with functions, using it doesn't mean you
  have to rewrite, but every time you write one, you should ask yourself
  the question as to whether the task you're doing isn't better suited
  to another language.

Finally, whenever you use a ``$`` in Bash (parameter expansion), you
must use quotation marks. Always only ever use quotation marks. Never
forget. Never be lazy. This is a security hazard. As previously
mentioned, Bash is an injection honeypot. There are a few cases where
you don't need the quotation marks. They are the exceptions. Do not
learn them. Just use quotes all the time. It is always correct.
