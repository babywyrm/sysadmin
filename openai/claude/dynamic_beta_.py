#!/usr/bin/env python3
import os
import sys
import anthropic
from pathlib import Path
import json
import time
from dataclasses import dataclass
from typing import List, Dict, Optional, Set
from rich.console import Console
from rich.progress import Progress, TaskID
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.tree import Tree
from rich import box
import re

# Install with: pip install rich anthropic
# Define which file extensions we want to analyze
SUPPORTED_EXTENSIONS = {'.py', '.go', '.java', '.js', '.ts', '.php', '.rb', '.jsx', '.tsx', '.cpp', '.c', '.h', '.cs', '.rs'}

@dataclass
class FileAnalysis:
    """Data structure to hold analysis results for a single file"""
    file_path: Path
    relevance: str
    insights: List[Dict]
    summary: str
    overall_assessment: str

@dataclass
class BatchResult:
    """Data structure to hold analysis results for a batch of related files"""
    files: List[Path]
    combined_insights: List[Dict]
    cross_file_patterns: List[str]
    batch_summary: str

class SmartCodeAnalyzer:
    """Main analyzer class that handles intelligent batch analysis of codebases"""
    
    def __init__(self):
        # Initialize rich console for beautiful terminal output
        self.console = Console()
        # Claude client will be initialized later with API key
        self.client = None
        
    def get_api_key(self):
        """
        Retrieve and validate the Claude API key from environment variables.
        Exits the program if no key is found.
        """
        api_key = os.getenv('CLAUDE_API_KEY')
        if not api_key:
            self.console.print("[bold red]Error: CLAUDE_API_KEY environment variable not set[/bold red]")
            self.console.print("Please set it with: [bold]export CLAUDE_API_KEY=your_api_key_here[/bold]")
            sys.exit(1)
        return api_key

    def scan_repo_files(self, repo_path) -> List[Path]:
        """
        Recursively scan the repository for supported code files.
        Filters out common build/cache directories and overly large files.
        
        Args:
            repo_path: Path to the repository root
            
        Returns:
            List of Path objects representing analyzable files
        """
        repo = Path(repo_path)
        files = []
        
        # Directories to skip during scanning (common build/cache/dependency folders)
        skip_dirs = {'.git', 'node_modules', '__pycache__', 'vendor', 'build', 'dist', '.pytest_cache', 'target', '.next', 'coverage'}
        
        # Walk through all files in the repository
        for file_path in repo.rglob("*"):
            if (file_path.is_file() and 
                file_path.suffix in SUPPORTED_EXTENSIONS and 
                not any(skip in file_path.parts for skip in skip_dirs) and
                file_path.stat().st_size < 150000):  # Skip files larger than 150KB to avoid token limits
                files.append(file_path)
        
        return sorted(files)

    def group_files_intelligently(self, files: List[Path], question: str) -> List[List[Path]]:
        """
        Group files into related batches for context-aware analysis.
        This is key to understanding how files work together rather than analyzing them in isolation.
        
        Grouping strategy:
        1. Group by directory structure (files in same directory likely related)
        2. Group by file patterns (tests, configs, models, etc.)
        3. Keep batch sizes reasonable (max 3 files per batch for context)
        
        Args:
            files: List of all files to analyze
            question: The analysis question (could be used for smarter grouping in future)
            
        Returns:
            List of file batches, where each batch is a list of related files
        """
        file_groups = {}
        
        for file in files:
            # Extract directory structure for grouping
            parts = file.parts[:-1]  # All directory parts except the filename
            
            # Create a grouping key based on directory depth
            if len(parts) >= 2:
                # Use the last 2 directory levels as the base group key
                group_key = "/".join(parts[-2:])
            else:
                # For files in root or shallow directories
                group_key = "/".join(parts) if parts else "root"
            
            # Enhance grouping by detecting file type patterns
            # This helps group functionally related files even if in different directories
            if file.name.endswith(('_test.py', '.test.js', '_spec.rb')):
                group_key += "_tests"  # Group all test files together
            elif file.name in ('__init__.py', 'index.js', 'main.py', 'app.py'):
                group_key += "_entry"  # Group entry point files
            elif 'model' in file.name.lower() or 'schema' in file.name.lower():
                group_key += "_data"  # Group data model files
            elif 'config' in file.name.lower() or 'setting' in file.name.lower():
                group_key += "_config"  # Group configuration files
            
            # Add file to the appropriate group
            if group_key not in file_groups:
                file_groups[group_key] = []
            file_groups[group_key].append(file)
        
        # Convert grouped files into reasonable-sized batches
        batches = []
        for group_files in file_groups.values():
            if len(group_files) <= 3:
                # Small groups can be analyzed as a single batch
                batches.append(group_files)
            else:
                # Large groups need to be split into smaller batches
                # This ensures each batch doesn't exceed token limits
                for i in range(0, len(group_files), 3):
                    batches.append(group_files[i:i+3])
        
        return batches

    def create_batch_analysis_prompt(self, file_batch: List[Path], question: str) -> str:
        """
        Create a comprehensive prompt for Claude to analyze a batch of related files.
        This prompt is designed to find cross-file patterns and relationships.
        
        Args:
            file_batch: List of related files to analyze together
            question: The specific question we want answered about the codebase
            
        Returns:
            Formatted prompt string for Claude analysis
        """
        batch_content = ""
        file_summaries = []
        
        # Read and combine all files in the batch
        for file_path in file_batch:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read().strip()
                    if content:
                        # Add file separator and content to batch
                        batch_content += f"\n\n=== FILE: {file_path} ===\n{content}"
                        # Track file info for the summary
                        file_summaries.append(f"- {file_path.name} ({len(content)} chars)")
            except Exception as e:
                # Skip files that can't be read, but don't fail the whole batch
                continue
        
        # Create a comprehensive analysis prompt that emphasizes relationships
        return f"""You are an expert code analyst. Analyze this batch of related files together to understand their relationships and answer the specific question.

ANALYSIS QUESTION: {question}

FILES IN THIS BATCH:
{chr(10).join(file_summaries)}

CONTEXT: These files are grouped together because they appear to be related (same directory, similar patterns, or functional relationships). Look for:
1. Cross-file dependencies and interactions
2. Shared patterns or inconsistencies
3. How they collectively address the question
4. Opportunities for improvements that span multiple files

PROVIDE OUTPUT IN JSON FORMAT:
{{
  "batch_summary": "Overview of how these files work together",
  "cross_file_insights": [
    {{
      "pattern": "What pattern or relationship spans multiple files",
      "files_involved": ["file1.py", "file2.py"],
      "finding": "Detailed description of the finding",
      "impact": "How this relates to the question asked",
      "recommendation": "Specific actionable recommendation"
    }}
  ],
  "individual_files": [
    {{
      "file_path": "path/to/file.py",
      "relevance": "HIGH|MEDIUM|LOW|NONE",
      "key_insights": [
        {{
          "finding": "Specific finding in this file",
          "line_number": 45,
          "code_snippet": "relevant code",
          "explanation": "Why this matters for the question"
        }}
      ]
    }}
  ],
  "recommendations": [
    "Prioritized list of actionable recommendations for this batch"
  ]
}}

BATCH CODE TO ANALYZE:
{batch_content}

Focus on findings that directly relate to: "{question}"
Be specific about cross-file relationships and systemic patterns."""

    def analyze_batch_with_claude(self, file_batch: List[Path], question: str) -> Optional[BatchResult]:
        """
        Send a batch of files to Claude for analysis and parse the results.
        This is where the actual AI analysis happens.
        
        Args:
            file_batch: List of related files to analyze together
            question: The analysis question
            
        Returns:
            BatchResult object with parsed insights, or None if analysis failed
        """
        try:
            # Create the analysis prompt
            prompt = self.create_batch_analysis_prompt(file_batch, question)
            
            # Send request to Claude
            response = self.client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=4000,  # Allow for comprehensive analysis
                messages=[{"role": "user", "content": prompt}]
            )
            
            # Extract and parse the response
            response_text = response.content[0].text
            parsed = self.parse_json_response(response_text)
            
            # Convert parsed JSON into our BatchResult structure
            if parsed:
                return BatchResult(
                    files=file_batch,
                    combined_insights=parsed.get('cross_file_insights', []),
                    cross_file_patterns=parsed.get('recommendations', []),
                    batch_summary=parsed.get('batch_summary', '')
                )
            
        except Exception as e:
            # Log the error but don't fail the entire analysis
            self.console.print(f"   [red]Error analyzing batch: {str(e)}[/red]")
            
        return None

    def parse_json_response(self, response_text: str) -> Optional[Dict]:
        """
        Extract JSON from Claude's response, which may include additional text.
        Claude sometimes wraps JSON in explanatory text, so we need to find the JSON portion.
        
        Args:
            response_text: Raw response from Claude
            
        Returns:
            Parsed JSON dictionary, or None if parsing failed
        """
        try:
            # Find the JSON portion of the response
            start = response_text.find('{')
            end = response_text.rfind('}') + 1
            
            if start >= 0 and end > start:
                json_str = response_text[start:end]
                return json.loads(json_str)
        except Exception:
            # If JSON parsing fails, we'll handle it gracefully
            pass
        return None

    def display_startup_banner(self, repo_path: str, question: str, file_count: int):
        """
        Display a professional startup banner with analysis information.
        This helps users understand what's about to happen.
        
        Args:
            repo_path: Path to the repository being analyzed
            question: The analysis question
            file_count: Number of files found for analysis
        """
        banner = Panel.fit(
            f"[bold blue]Smart Code Analyzer[/bold blue]\n\n"
            f"[bold]Repository:[/bold] {repo_path}\n"
            f"[bold]Question:[/bold] {question}\n"
            f"[bold]Files Found:[/bold] {file_count}\n"
            f"[bold]Engine:[/bold] Claude 3.5 Sonnet",
            border_style="blue",
            title="[bold white]Analysis Starting[/bold white]"
        )
        
        self.console.print(banner)
        self.console.print()

    def display_batch_results(self, batch_results: List[BatchResult], question: str):
        """
        Display comprehensive analysis results in a structured, readable format.
        This is where we present all the insights we've gathered.
        
        Args:
            batch_results: List of BatchResult objects from analysis
            question: The original analysis question for context
        """
        
        # Calculate summary statistics across all batches
        total_insights = sum(len(batch.combined_insights) for batch in batch_results)
        total_files = sum(len(batch.files) for batch in batch_results)
        
        # Create a summary table showing high-level metrics
        summary_table = Table(title="Analysis Summary", box=box.ROUNDED)
        summary_table.add_column("Metric", style="bold")
        summary_table.add_column("Value", style="green")
        
        summary_table.add_row("Total Batches Analyzed", str(len(batch_results)))
        summary_table.add_row("Total Files Processed", str(total_files))
        summary_table.add_row("Cross-File Insights Found", str(total_insights))
        
        self.console.print(summary_table)
        self.console.print()
        
        # Display detailed findings if we found any insights
        if total_insights > 0:
            findings_panel = Panel(
                "[bold green]Key Findings[/bold green]",
                border_style="green"
            )
            self.console.print(findings_panel)
            
            # Process each batch and display its insights
            for i, batch in enumerate(batch_results, 1):
                if batch.combined_insights:
                    # Show which files were analyzed together in this batch
                    self.console.print(f"\n[bold blue]Batch {i}:[/bold blue] {', '.join([f.name for f in batch.files])}")
                    
                    # Display the batch summary if available
                    if batch.batch_summary:
                        self.console.print(f"[italic]{batch.batch_summary}[/italic]\n")
                    
                    # Create a detailed insights table for this batch
                    insights_table = Table(box=box.SIMPLE)
                    insights_table.add_column("Finding", style="yellow", width=40)
                    insights_table.add_column("Files", style="cyan", width=20)
                    insights_table.add_column("Recommendation", style="green", width=40)
                    
                    # Add each insight as a table row
                    for insight in batch.combined_insights:
                        pattern = insight.get('pattern', 'Unknown pattern')
                        files = ', '.join(insight.get('files_involved', []))
                        recommendation = insight.get('recommendation', 'No recommendation')
                        
                        # Truncate long text to keep table readable
                        insights_table.add_row(
                            pattern[:100] + "..." if len(pattern) > 100 else pattern,
                            files[:25] + "..." if len(files) > 25 else files,
                            recommendation[:100] + "..." if len(recommendation) > 100 else recommendation
                        )
                    
                    self.console.print(insights_table)
        
        # Collect and display top recommendations across all batches
        all_recommendations = []
        for batch in batch_results:
            all_recommendations.extend(batch.cross_file_patterns)
        
        if all_recommendations:
            self.console.print()
            recommendations_panel = Panel(
                "[bold yellow]Top Recommendations[/bold yellow]",
                border_style="yellow"
            )
            self.console.print(recommendations_panel)
            
            # Show the top 8 most important recommendations
            for i, rec in enumerate(all_recommendations[:8], 1):
                self.console.print(f"  {i}. {rec}")

    def get_question(self) -> str:
        """
        Get the analysis question from command line arguments or interactive input.
        Provides helpful examples if the user needs to enter a question interactively.
        
        Returns:
            The analysis question string
        """
        # Check if question was provided as command line argument
        if len(sys.argv) >= 3:
            return " ".join(sys.argv[2:])
        else:
            # Interactive mode - prompt user with examples
            self.console.print("[bold cyan]What would you like to analyze about this codebase?[/bold cyan]")
            self.console.print("[dim]Examples:[/dim]")
            examples = [
                "How could we improve the data model?",
                "What are the main architectural patterns used?", 
                "Where are the performance bottlenecks?",
                "How can we improve error handling?",
                "What security improvements should we make?"
            ]
            
            # Display example questions to help users understand what to ask
            for example in examples:
                self.console.print(f"  [dim]- {example}[/dim]")
            
            self.console.print()
            question = input("Enter your question: ").strip()
            if not question:
                self.console.print("[red]No question provided. Exiting.[/red]")
                sys.exit(1)
            return question

    def run_analysis(self, repo_path: str):
        """
        Main analysis pipeline that orchestrates the entire process.
        This method coordinates all the steps from file discovery to result display.
        
        Args:
            repo_path: Path to the repository to analyze
        """
        
        # Step 1: Initialize Claude client with API key
        api_key = self.get_api_key()
        self.client = anthropic.Anthropic(api_key=api_key)
        
        # Step 2: Get the analysis question from user
        question = self.get_question()
        
        # Step 3: Scan repository for analyzable files
        with self.console.status("[bold green]Scanning repository...") as status:
            all_files = self.scan_repo_files(repo_path)
            status.update(f"[bold green]Found {len(all_files)} files")
            time.sleep(0.5)  # Brief pause to show status
        
        # Exit early if no files found
        if not all_files:
            self.console.print("[red]No supported code files found in repository.[/red]")
            sys.exit(1)
        
        # Step 4: Display analysis information to user
        self.display_startup_banner(repo_path, question, len(all_files))
        
        # Step 5: Group files into intelligent batches for context-aware analysis
        with self.console.status("[bold yellow]Organizing files into analysis batches..."):
            file_batches = self.group_files_intelligently(all_files, question)
            time.sleep(0.3)
        
        self.console.print(f"[bold green]✓[/bold green] Organized into {len(file_batches)} analysis batches")
        self.console.print()
        
        # Step 6: Analyze each batch with Claude and collect results
        batch_results = []
        
        with Progress() as progress:
            # Create progress bar for the analysis phase
            main_task = progress.add_task(
                "[bold blue]Analyzing code batches...", 
                total=len(file_batches)
            )
            
            # Process each batch sequentially
            for i, batch in enumerate(file_batches, 1):
                # Update progress bar with current batch info
                batch_desc = f"Batch {i}/{len(file_batches)}: {', '.join([f.name for f in batch])}"
                progress.update(main_task, description=f"[bold blue]{batch_desc}[/bold blue]")
                
                # Analyze this batch with Claude
                result = self.analyze_batch_with_claude(batch, question)
                if result:
                    batch_results.append(result)
                
                # Update progress and add small delay for rate limiting
                progress.update(main_task, advance=1)
                time.sleep(0.5)  # Respect API rate limits
        
        self.console.print()
        
        # Step 7: Display comprehensive results
        if batch_results:
            self.display_batch_results(batch_results, question)
        else:
            self.console.print("[red]No analysis results were generated. Please check your API key and try again.[/red]")

def main():
    """
    Entry point for the script. Handles command line arguments and starts analysis.
    """
    # Check if user provided required arguments
    if len(sys.argv) < 2:
        console = Console()
        console.print("[bold red]Usage:[/bold red] python smart_analyzer.py <repo_path> [question]")
        console.print("  [dim]If no question is provided, you'll be prompted to enter one.[/dim]")
        console.print()
        console.print("[bold yellow]Setup:[/bold yellow] export CLAUDE_API_KEY=your_api_key_here")
        console.print()
        console.print("[bold cyan]Features:[/bold cyan]")
        console.print("  • Smart batch analysis of related files")
        console.print("  • Cross-file pattern detection")
        console.print("  • Rich interactive output")
        console.print("  • Context-aware recommendations")
        sys.exit(1)
    
    # Validate that the repository path exists
    repo_path = sys.argv[1]
    if not os.path.exists(repo_path):
        console = Console()
        console.print(f"[bold red]Error:[/bold red] Repository path '{repo_path}' does not exist")
        sys.exit(1)
    
    # Create analyzer instance and run the analysis
    analyzer = SmartCodeAnalyzer()
    analyzer.run_analysis(repo_path)

if __name__ == "__main__":
    main()
