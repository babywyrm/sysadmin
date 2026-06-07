#!/usr/bin/env python3
"""
Smart Code Analyzer - Intelligent batch analysis powered by Claude.
This script analyzes codebases by intelligently grouping related files,
sending them to the Claude API for analysis against a specific user question,
and generating structured reports in various formats.
"""

import os
import sys
import json
import time
import argparse
import re
from datetime import datetime
from dataclasses import dataclass
from pathlib import Path
from typing import List, Dict, Optional
from enum import Enum

import anthropic
from rich.console import Console
from rich.progress import Progress
from rich.table import Table
from rich.panel import Panel
from rich import box

# Ensure required packages are installed: pip install rich anthropic

class OutputFormat(Enum):
    """Enumeration for supported output formats."""
    CONSOLE = "console"
    JSON = "json" 
    MARKDOWN = "markdown"
    HTML = "html"

# --- Constants ---
# Defines which file extensions are eligible for analysis.
SUPPORTED_EXTENSIONS = {'.py', '.go', '.java', '.js', '.ts', '.php', '.rb', '.jsx', '.tsx', '.cpp', '.c', '.h', '.cs', '.rs'}
# Defines directories to be skipped during file discovery to avoid analyzing dependencies or build artifacts.
SKIP_DIRECTORIES = {'.git', 'node_modules', '__pycache__', 'vendor', 'build', 'dist', '.pytest_cache', 'target', '.next', 'coverage', '.venv'}
# Defines operational limits to manage cost, performance, and API constraints.
MAX_FILE_SIZE, MAX_BATCH_SIZE, API_RATE_LIMIT_DELAY = 150_000, 3, 0.5

# --- Data Structures ---
@dataclass
class BatchResult:
    """Holds the analysis results for a single batch of related files."""
    files: List[Path]
    combined_insights: List[Dict]
    cross_file_patterns: List[str]
    batch_summary: str

@dataclass
class AnalysisReport:
    """Represents the complete, aggregated analysis report for the entire run."""
    repo_path: str
    question: str
    timestamp: str
    total_files: int
    total_batches: int
    total_insights: int
    batch_results: List[BatchResult]
    all_recommendations: List[str]
    
    def to_dict(self) -> Dict:
        """Serializes the report object to a dictionary for JSON output."""
        return {
            "analysis_metadata": {
                "repository_path": self.repo_path, "analysis_question": self.question,
                "timestamp": self.timestamp, "total_files_analyzed": self.total_files,
                "total_batches": self.total_batches, "total_insights_found": self.total_insights
            },
            "batch_analysis": [{
                "files": [str(f) for f in batch.files], "batch_summary": batch.batch_summary,
                "insights": batch.combined_insights, "recommendations": batch.cross_file_patterns
            } for batch in self.batch_results],
            "summary_recommendations": self.all_recommendations
        }

# --- Core Logic Classes ---
class SecurityValidator:
    """Provides static methods for validating file system paths and files."""
    @staticmethod
    def validate_repo_path(path: str) -> Path:
        """Ensures the repository path is a valid, safe, and accessible directory."""
        repo_path = Path(path).resolve()
        if not repo_path.exists(): raise ValueError(f"Repository path does not exist: {path}")
        if not repo_path.is_dir(): raise ValueError(f"Repository path is not a directory: {path}")
        return repo_path
    
    @staticmethod
    def validate_file_for_analysis(file_path: Path) -> bool:
        """Checks if a file is suitable for analysis based on size, extension, and location."""
        try:
            if not file_path.is_file(): return False
            if file_path.stat().st_size > MAX_FILE_SIZE: return False
            if file_path.suffix not in SUPPORTED_EXTENSIONS: return False
            if any(skip in file_path.parts for skip in SKIP_DIRECTORIES): return False
            with open(file_path, 'r', encoding='utf-8', errors='strict') as f: f.read(1024)
            return True
        except (OSError, UnicodeDecodeError, PermissionError):
            return False

class FileAnalyzer:
    """Handles file discovery and intelligent grouping."""
    def __init__(self, repo_path: Path):
        self.repo_path = repo_path
    
    def discover_files(self) -> List[Path]:
        """Scans the repository and returns a list of valid files for analysis."""
        return sorted([fp for fp in self.repo_path.rglob("*") if SecurityValidator.validate_file_for_analysis(fp)])
    
    def group_files_intelligently(self, files: List[Path]) -> List[List[Path]]:
        """Groups files into small, related batches to provide context to the AI."""
        file_groups: Dict[str, List[Path]] = {}
        for file in files:
            group_key = self._calculate_group_key(file)
            file_groups.setdefault(group_key, []).append(file)
        
        batches = []
        for group_files in file_groups.values():
            for i in range(0, len(group_files), MAX_BATCH_SIZE):
                batches.append(group_files[i:i + MAX_BATCH_SIZE])
        return batches
    
    def _calculate_group_key(self, file: Path) -> str:
        """Determines a grouping key for a file based on its path and name patterns."""
        parts = file.parts[:-1]
        group_key = "/".join(parts[-2:]) if len(parts) >= 2 else "/".join(parts) or "root"
        name = file.name.lower()
        if any(p in name for p in ['_test', '.test', '_spec']): group_key += "_tests"
        elif file.name in {'__init__.py', 'index.js', 'main.py', 'app.py'}: group_key += "_entry"
        elif any(p in name for p in ['model', 'schema']): group_key += "_data"
        elif any(p in name for p in ['config', 'setting']): group_key += "_config"
        return group_key

class OutputFormatter:
    """Provides static methods for formatting the final report into different file types."""
    @staticmethod
    def format_json(report: AnalysisReport) -> str:
        """Formats the report as a JSON string."""
        return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)
    
    @staticmethod
    def format_markdown(report: AnalysisReport) -> str:
        """Formats the report as a Markdown document."""
        md_lines = [f"# Code Analysis Report\n", f"**Repository:** `{report.repo_path}`  ", f"**Question:** {report.question}  ", f"**Analysis Date:** {report.timestamp}\n", "---\n", "## Detailed Findings\n"]
        for i, batch in enumerate(report.batch_results, 1):
            if batch.combined_insights:
                md_lines.extend([f"### Batch {i}: {', '.join(f.name for f in batch.files)}\n", f"**Overview:** {batch.batch_summary}\n" if batch.batch_summary else "", "| Finding | Files Involved | Recommendation |", "|---|---|---|"])
                for insight in batch.combined_insights:
                    md_lines.append(f"| {insight.get('pattern', '').replace('|', '')} | {', '.join(insight.get('files_involved', []))} | {insight.get('recommendation', '').replace('|', '')} |")
                md_lines.append("")
        if report.all_recommendations:
            md_lines.extend(["## Top Recommendations\n"] + [f"{i}. {rec}" for i, rec in enumerate(report.all_recommendations, 1)])
        return "\n".join(md_lines)
    
    @staticmethod
    def format_html(report: AnalysisReport, dark_mode: bool = False) -> str:
        """
        Formats the report as a self-contained HTML document.
        
        Args:
            report: The complete analysis report.
            dark_mode: If True, applies a dark theme to the HTML output.
        """
        body_class = "dark-mode" if dark_mode else ""
        batch_sections, recommendations_html = [], ""
        for i, batch in enumerate(report.batch_results, 1):
            if batch.combined_insights:
                rows = [f"<tr><td>{i.get('pattern', '')}</td><td><code>{', '.join(i.get('files_involved', []))}</code></td><td>{i.get('recommendation', '')}</td></tr>" for i in batch.combined_insights]
                batch_sections.append(f"""<div class="batch-section"><h3 class="batch-title">Batch {i}: {', '.join(f.name for f in batch.files)}</h3>{"<p><strong>Overview:</strong> " + batch.batch_summary + "</p>" if batch.batch_summary else ""}<table><thead><tr><th>Finding</th><th>Files Involved</th><th>Recommendation</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div>""")
        if report.all_recommendations:
            rec_items = [f"<li>{rec}</li>" for rec in report.all_recommendations]
            recommendations_html = f"""<div class="recommendations"><h2>Top Recommendations</h2><ol>{''.join(rec_items)}</ol></div>"""
        
        return f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Code Analysis Report</title><style>body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;line-height:1.6;margin:0;padding:20px;background:#f5f5f5;color:#212529;transition:background-color .3s,color .3s}}.container{{max-width:1200px;margin:0 auto;background:white;padding:30px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.1);transition:background-color .3s}}.header{{background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:white;padding:20px;border-radius:8px;margin-bottom:30px}}.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:15px;margin-bottom:30px}}.stat-card{{background:#f8f9fa;padding:15px;border-radius:6px;border-left:4px solid #667eea;transition:background-color .3s}}.batch-section{{margin-bottom:30px;padding:20px;border:1px solid #e0e0e0;border-radius:6px}}table{{width:100%;border-collapse:collapse;margin:15px 0}}th,td{{padding:12px;text-align:left;border-bottom:1px solid #ddd}}th{{background-color:#f8f9fa;font-weight:600}}.recommendations{{background:#fff3cd;padding:20px;border-radius:6px;border-left:4px solid #ffc107}}code{{background:#e9ecef;padding:2px 4px;border-radius:3px;font-family:Monaco,monospace}}body.dark-mode{{background-color:#121212;color:#e0e0e0}}.dark-mode .container{{background:#1e1e1e;box-shadow:0 2px 10px rgba(0,0,0,.5)}}.dark-mode .stat-card{{background:#2a2a2a;border-left-color:#8a98ff}}.dark-mode .batch-section{{border-color:#444}}.dark-mode th,.dark-mode td{{border-color:#444}}.dark-mode th{{background-color:#333}}.dark-mode .recommendations{{background:#4a412a;border-left-color:#ffc107}}.dark-mode code{{background:#3a3a3a;color:#d4d4d4}}</style></head><body class="{body_class}"><div class="container"><div class="header"><h1>Code Analysis Report</h1><p><strong>Repository:</strong> <code>{report.repo_path}</code></p><p><strong>Question:</strong> {report.question}</p><p><strong>Generated:</strong> {report.timestamp}</p></div><div class="stats"><div class="stat-card"><h3>Files Analyzed</h3><p style="font-size:24px;font-weight:bold;color:#667eea">{report.total_files}</p></div><div class="stat-card"><h3>Batches Processed</h3><p style="font-size:24px;font-weight:bold;color:#667eea">{report.total_batches}</p></div><div class="stat-card"><h3>Insights Found</h3><p style="font-size:24px;font-weight:bold;color:#667eea">{report.total_insights}</p></div></div><h2>Detailed Findings</h2>{''.join(batch_sections)}{recommendations_html}<div style="margin-top:40px;padding-top:20px;border-top:1px solid #ddd;text-align:center;color:#666"><p><em>Report generated by Smart Code Analyzer powered by Claude</em></p></div></div></body></html>"""

class SmartCodeAnalyzer:
    """Orchestrates the entire code analysis process."""
    def __init__(self, dark_mode: bool = False):
        self.console = Console()
        self.client: Optional[anthropic.Anthropic] = None
        self.dark_mode = dark_mode
        
    def initialize_client(self) -> None:
        """Initializes the Anthropic client, ensuring the API key is set."""
        api_key = os.getenv('CLAUDE_API_KEY')
        if not api_key:
            self.console.print("[bold red]Error: CLAUDE_API_KEY environment variable not set.[/bold red]")
            sys.exit(1)
        self.client = anthropic.Anthropic(api_key=api_key)
    
    def analyze_repository(self, repo_path: str, question: str) -> AnalysisReport:
        """Executes the main analysis pipeline from file discovery to report generation."""
        self.initialize_client()
        validated_repo_path = SecurityValidator.validate_repo_path(repo_path)
        
        with self.console.status("[bold green]Scanning repository...[/bold green]"):
            file_analyzer = FileAnalyzer(validated_repo_path)
            all_files = file_analyzer.discover_files()
        
        if not all_files:
            raise ValueError("No supported code files found in repository")
        
        self._display_startup_info(repo_path, question, len(all_files))
        
        with self.console.status("[bold yellow]Organizing files into analysis batches...[/bold yellow]"):
            file_batches = file_analyzer.group_files_intelligently(all_files)
        self.console.print(f"[bold green]✓[/bold green] Organized into {len(file_batches)} analysis batches\n")
        
        batch_results = self._analyze_batches(file_batches, question)
        return self._create_report(repo_path, question, batch_results, all_files)
    
    def _analyze_batches(self, file_batches: List[List[Path]], question: str) -> List[BatchResult]:
        """Processes each file batch with a live progress bar."""
        batch_results = []
        with Progress(console=self.console) as progress:
            task = progress.add_task("[bold blue]Analyzing code batches...", total=len(file_batches))
            for i, batch in enumerate(file_batches, 1):
                progress.update(task, description=f"[bold blue]Batch {i}/{len(file_batches)}[/bold blue]")
                result = self._analyze_single_batch(batch, question)
                if result: batch_results.append(result)
                progress.advance(task)
                time.sleep(API_RATE_LIMIT_DELAY)
        self.console.print()
        return batch_results
    
    def _analyze_single_batch(self, file_batch: List[Path], question: str) -> Optional[BatchResult]:
        """Sends a single batch to the Claude API for analysis."""
        try:
            prompt = self._create_analysis_prompt(file_batch, question)
            response = self.client.messages.create(model="claude-3-5-sonnet-20241022", max_tokens=4000, messages=[{"role": "user", "content": prompt}])
            parsed = self._parse_json_response(response.content[0].text)
            if parsed:
                return BatchResult(files=file_batch, combined_insights=parsed.get('cross_file_insights', []), cross_file_patterns=parsed.get('recommendations', []), batch_summary=parsed.get('batch_summary', ''))
        except Exception as e:
            self.console.print(f"[red]Error analyzing batch: {e}[/red]")
        return None
    
    def _create_analysis_prompt(self, file_batch: List[Path], question: str) -> str:
        """Constructs the detailed prompt for the Claude API."""
        batch_content, file_summaries = [], []
        for fp in file_batch:
            try:
                content = fp.read_text(encoding='utf-8', errors='replace').strip()
                if content:
                    batch_content.append(f"\n=== FILE: {fp} ===\n{content}")
                    file_summaries.append(f"- {fp.name} ({len(content)} chars)")
            except Exception: continue
        
        return f"""You are an expert code analyst. Analyze this batch of related files together to understand their relationships and answer the specific question.
ANALYSIS QUESTION: {question}
FILES IN THIS BATCH:
{chr(10).join(file_summaries)}
CONTEXT: These files are grouped together. Look for cross-file dependencies, shared patterns, and how they collectively address the question.
PROVIDE OUTPUT IN JSON FORMAT:
{{
  "batch_summary": "Overview of how these files work together",
  "cross_file_insights": [
    {{
      "pattern": "A pattern spanning multiple files",
      "files_involved": ["file1.py", "file2.py"],
      "finding": "Detailed description",
      "impact": "How this relates to the question",
      "recommendation": "Specific actionable recommendation"
    }}
  ],
  "recommendations": ["Prioritized list of actionable recommendations"]
}}
BATCH CODE TO ANALYZE:
{''.join(batch_content)}
Focus on findings that directly relate to: "{question}"
Be specific about cross-file relationships and systemic patterns."""
    
    def _parse_json_response(self, response_text: str) -> Optional[Dict]:
        """Safely extracts and parses a JSON object from the API's text response."""
        try:
            match = re.search(r'\{.*\}', response_text, re.DOTALL)
            if match: return json.loads(match.group(0))
        except json.JSONDecodeError:
            self.console.print("[yellow]Warning: Could not parse JSON from an API response.[/yellow]")
        return None
    
    def _create_report(self, repo_path: str, question: str, batch_results: List[BatchResult], all_files: List[Path]) -> AnalysisReport:
        """Aggregates all batch results into a final report object."""
        return AnalysisReport(repo_path=repo_path, question=question, timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"), total_files=len(all_files), total_batches=len(batch_results), total_insights=sum(len(b.combined_insights) for b in batch_results), batch_results=batch_results, all_recommendations=[rec for b in batch_results for rec in b.cross_file_patterns][:8])
    
    def save_reports(self, report: AnalysisReport, formats: List[OutputFormat], output_file_base: Optional[str]) -> None:
        """Saves the analysis report to files in the specified formats."""
        if output_file_base:
            base_path = Path(output_file_base).with_suffix('')
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            repo_name = Path(report.repo_path).name
            base_path = Path(f"analysis_{repo_name}_{timestamp}")

        for fmt in formats:
            if fmt == OutputFormat.CONSOLE: continue
            output_path = base_path.with_suffix(f".{fmt.value}")
            try:
                content = ""
                if fmt == OutputFormat.JSON: content = OutputFormatter.format_json(report)
                elif fmt == OutputFormat.MARKDOWN: content = OutputFormatter.format_markdown(report)
                elif fmt == OutputFormat.HTML: content = OutputFormatter.format_html(report, self.dark_mode)
                
                output_path.write_text(content, encoding='utf-8')
                self.console.print(f"[bold green]✓ Report saved to: {output_path}[/bold green]")
            except Exception as e:
                self.console.print(f"[red]Error saving {fmt.value} report: {e}[/red]")
    
    def display_console_report(self, report: AnalysisReport) -> None:
        """Displays a summary of the analysis results in the console."""
        if report.total_insights == 0 and not report.all_recommendations:
            self.console.print("[yellow]Analysis complete. No specific insights or recommendations were generated.[/yellow]")
            return

        summary_table = Table(title="Analysis Summary", box=box.ROUNDED)
        summary_table.add_column("Metric", style="bold"); summary_table.add_column("Value", style="green")
        summary_table.add_row("Total Batches", str(report.total_batches))
        summary_table.add_row("Total Files", str(report.total_files))
        summary_table.add_row("Insights Found", str(report.total_insights))
        self.console.print(summary_table)

        if report.total_insights > 0:
            self.console.print(Panel("[bold green]Key Findings[/bold green]", border_style="green"))
            for i, batch in enumerate(report.batch_results, 1):
                if batch.combined_insights:
                    self.console.print(f"\n[bold blue]Batch {i}:[/bold blue] {', '.join(f.name for f in batch.files)}")
                    if batch.batch_summary: self.console.print(f"[italic]{batch.batch_summary}[/italic]\n")
                    
                    insights_table = Table(box=box.SIMPLE)
                    insights_table.add_column("Finding", style="yellow", width=40)
                    insights_table.add_column("Files", style="cyan", width=20)
                    insights_table.add_column("Recommendation", style="green", width=40)
                    for insight in batch.combined_insights:
                        insights_table.add_row(insight.get('pattern', ''), ', '.join(insight.get('files_involved', [])), insight.get('recommendation', ''))
                    self.console.print(insights_table)
        
        if report.all_recommendations:
            self.console.print(Panel("[bold yellow]Top Recommendations[/bold yellow]", border_style="yellow", expand=False))
            for i, rec in enumerate(report.all_recommendations, 1):
                self.console.print(f"  {i}. {rec}")
    
    def _display_startup_info(self, repo_path: str, question: str, file_count: int) -> None:
        """Displays the initial analysis parameters in a panel."""
        banner = Panel.fit(f"[bold blue]Smart Code Analyzer[/bold blue]\n\n[bold]Repository:[/bold] {repo_path}\n[bold]Question:[/bold] {question}\n[bold]Files Found:[/bold] {file_count}\n[bold]Engine:[/bold] Claude 3.5 Sonnet", border_style="blue", title="[bold white]Analysis Starting[/bold white]")
        self.console.print(banner)

def create_parser() -> argparse.ArgumentParser:
    """Creates and configures the command-line argument parser."""
    examples = """
Examples:
  # Interactive console analysis (default)
  python smart_analyzer.py /path/to/repo
  
  # Generate HTML and Markdown reports simultaneously
  python smart_analyzer.py /path/to/repo "Find security issues" --format html markdown --output report
  
  # Generate a dark-themed HTML report
  python smart_analyzer.py /path/to/repo "Analyze architecture" --format html --dark-mode
    """
    parser = argparse.ArgumentParser(description='Smart Code Analyzer', formatter_class=argparse.RawDescriptionHelpFormatter, epilog=examples)
    parser.add_argument('repo_path', help='Path to the repository to analyze')
    parser.add_argument('question', nargs='?', help='Analysis question (interactive prompt if not provided)')
    parser.add_argument('--format', '-f', type=OutputFormat, nargs='*', default=[OutputFormat.CONSOLE], help='One or more output formats (default: console)')
    parser.add_argument('--output', '-o', help='Base output file path (e.g., "my_report"). Suffix is ignored.')
    parser.add_argument('--dark-mode', action='store_true', help='Generate HTML report with a dark theme.')
    return parser

def get_question_interactively() -> str:
    """Prompts the user to enter an analysis question if one was not provided."""
    console = Console()
    console.print("\n[bold cyan]What would you like to analyze about this codebase?[/bold cyan]")
    console.print("\n[dim]Popular analysis questions:[/dim]")
    examples = ["How can we improve the data model?", "What are the main architectural patterns?", "Where are the performance bottlenecks?", "What security vulnerabilities exist?"]
    for example in examples: console.print(f"  [dim]- {example}[/dim]")
    console.print()
    question = input("Enter your question: ").strip()
    if not question:
        console.print("[red]No question provided. Exiting.[/red]")
        sys.exit(1)
    return question

def main() -> None:
    """Main entry point for the script execution."""
    try:
        parser = create_parser()
        args = parser.parse_args()
        
        question = args.question if args.question else get_question_interactively()
        
        analyzer = SmartCodeAnalyzer(dark_mode=args.dark_mode)
        report = analyzer.analyze_repository(args.repo_path, question)
        
        file_formats = [f for f in args.format if f != OutputFormat.CONSOLE]
        
        if OutputFormat.CONSOLE in args.format:
            analyzer.display_console_report(report)
        
        if file_formats:
            analyzer.save_reports(report, file_formats, args.output)
    
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user.")
        sys.exit(1)
    except (ValueError, FileNotFoundError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
