#!/usr/bin/env python3
import os
import sys
import anthropic
from pathlib import Path
import json
import time

SUPPORTED_EXTENSIONS = {'.py', '.go', '.java', '.js', '.ts', '.php', '.rb', '.jsx', '.tsx'}

def get_api_key():
    """Get the Claude API key from environment variable"""
    api_key = os.getenv('CLAUDE_API_KEY')
    if not api_key:
        print("Error: CLAUDE_API_KEY environment variable not set")
        print("Please set it with: export CLAUDE_API_KEY=your_api_key_here")
        sys.exit(1)
    return api_key

def get_dynamic_prompt(file_path, code_content, question):
    return f"""You are an expert code analyst helping to answer specific questions about codebases.

FILE: {file_path}
LANGUAGE: {file_path.suffix}

QUESTION TO ANALYZE: {question}

Please analyze the following code in the context of the question above. 
Provide actionable insights and specific recommendations.

PROVIDE OUTPUT IN JSON FORMAT:
{{
  "file_path": "{file_path}",
  "relevance": "HIGH|MEDIUM|LOW|NONE",
  "insights": [
    {{
      "finding": "Description of what you found relevant to the question",
      "line_number": 45,
      "code_snippet": "relevant code snippet",
      "explanation": "Why this is relevant to the question",
      "recommendation": "Specific actionable recommendation"
    }}
  ],
  "summary": "Brief summary of findings for this file",
  "overall_assessment": "How this file relates to the question asked"
}}

CODE TO ANALYZE:
{code_content}

Focus on findings that directly relate to the question asked. Be specific and actionable."""

def analyze_file_with_claude(file_path, api_key, question):
    client = anthropic.Anthropic(api_key=api_key)
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
        if not content.strip():
            return None
        if len(content) > 100000:
            print(f"   Skipping {file_path} (file too large: {len(content)} chars)")
            return None
        print(f"   File size: {len(content)} characters")
        prompt = get_dynamic_prompt(file_path, content, question)
        response = client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=4000,
            messages=[{"role": "user", "content": prompt}]
        )
        return response.content[0].text
    except Exception as e:
        print(f"   Error analyzing {file_path}: {str(e)}")
        return None

def parse_json_response(response_text):
    try:
        start = response_text.find('{')
        end = response_text.rfind('}') + 1
        if start >= 0 and end > start:
            json_str = response_text[start:end]
            return json.loads(json_str)
    except:
        pass
    return None

def scan_repo_files(repo_path):
    repo = Path(repo_path)
    files = []
    skip_dirs = {'.git', 'node_modules', '__pycache__', 'vendor', 'build', 'dist', '.pytest_cache', 'target'}
    for file_path in repo.rglob("*"):
        if (file_path.is_file() and file_path.suffix in SUPPORTED_EXTENSIONS and not any(skip in file_path.parts for skip in skip_dirs)):
            files.append(file_path)
    return sorted(files)

def get_question():
    """Get the analysis question from user input or command line"""
    if len(sys.argv) >= 3:
        # Question provided as command line argument
        return " ".join(sys.argv[2:])
    else:
        # Prompt user for question
        print("What would you like to analyze about this codebase?")
        print("Examples:")
        print("  - How could we improve the data model?")
        print("  - What are the main architectural patterns used?")
        print("  - Where are the performance bottlenecks?")
        print("  - How can we improve error handling?")
        print()
        question = input("Enter your question: ").strip()
        if not question:
            print("No question provided. Exiting.")
            sys.exit(1)
        return question

def main():
    if len(sys.argv) < 2:
        print("Usage: python dynamic_analyzer.py <repo_path> [question]")
        print("  If no question is provided, you'll be prompted to enter one.")
        print()
        print("Setup: export CLAUDE_API_KEY=your_api_key_here")
        sys.exit(1)
    
    # Get API key from environment variable
    api_key = get_api_key()
    
    repo_path = sys.argv[1]
    if not os.path.exists(repo_path):
        print(f"Error: Repository path '{repo_path}' does not exist")
        sys.exit(1)
    
    question = get_question()
    
    print(f"Dynamic Code Analyzer")
    print(f"Repository: {repo_path}")
    print(f"Question: {question}")
    print(f"Engine: Claude 3.5 Sonnet")
    print()
    
    files = scan_repo_files(repo_path)
    print(f"Found {len(files)} code files to analyze")
    print()
    
    all_insights = []
    high_relevance_count = 0
    medium_relevance_count = 0
    
    for i, file_path in enumerate(files, 1):
        print(f"[{i}/{len(files)}] {file_path}")
        analysis = analyze_file_with_claude(file_path, api_key, question)
        if not analysis:
            continue
        
        parsed = parse_json_response(analysis)
        if parsed and 'insights' in parsed:
            insights = parsed['insights']
            relevance = parsed.get('relevance', 'UNKNOWN')
            print(f"   Relevance: {relevance}")
            print(f"   Found {len(insights)} insights")
            
            if relevance == 'HIGH':
                high_relevance_count += 1
            elif relevance == 'MEDIUM':
                medium_relevance_count += 1
            
            for insight in insights:
                finding = insight.get('finding', 'Unknown finding')
                line = insight.get('line_number', 'Unknown')
                recommendation = insight.get('recommendation', 'No recommendation')
                print(f"     Finding: {finding} (Line {line})")
                print(f"     Recommendation: {recommendation}")
            
            all_insights.extend(insights)
        else:
            print("   Raw analysis:")
            print(analysis[:500] + "..." if len(analysis) > 500 else analysis)
        
        print()
        time.sleep(1)
    
    print("=" * 60)
    print("ANALYSIS COMPLETE")
    print("=" * 60)
    print(f"Total files analyzed: {len(files)}")
    print(f"Total insights found: {len(all_insights)}")
    print(f"High relevance files: {high_relevance_count}")
    print(f"Medium relevance files: {medium_relevance_count}")
    
    if all_insights:
        print()
        print("Key Recommendations:")
        for i, insight in enumerate(all_insights[:5], 1):  # Show top 5
            rec = insight.get('recommendation', 'No recommendation')
            file_path = insight.get('file_path', 'Unknown file')
            print(f"  {i}. {rec} ({Path(file_path).name})")

if __name__ == "__main__":
    main()

##
##
