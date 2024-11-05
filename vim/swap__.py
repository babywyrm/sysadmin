import re

##
##

def parse_vim_swp(file_path):
    """Parse a Vim swap file and extract relevant information."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        # Initialize variables
        metadata = {}
        content = []

        # Regex patterns for extracting metadata
        metadata_patterns = {
            'owner': re.compile(r'owner:\s*(.*)'),
            'host': re.compile(r'host:\s*(.*)'),
            'timestamp': re.compile(r'timestamp:\s*(.*)'),
            'pid': re.compile(r'pid:\s*(.*)'),
            'mode': re.compile(r'mode:\s*(.*)'),
            'file': re.compile(r'file:\s*(.*)'),
        }

        # Parse metadata
        for line in lines:
            for key, pattern in metadata_patterns.items():
                match = pattern.match(line)
                if match:
                    metadata[key] = match.group(1).strip()

            # Collect content after metadata
            if line.startswith('# Content of'):
                continue
            if line.strip() == '#' or line.startswith('#'):
                continue
            content.append(line)

        # Join content to form the full original file content
        original_content = ''.join(content).strip()

        return {
            'metadata': metadata,
            'content': original_content,
        }

    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return None
    except Exception as e:
        print(f"Error: {e}")
        return None


if __name__ == "__main__":
    # Example usage
    swp_file_path = 'path/to/your/file.swp'  # Change this to your SWP file path
    result = parse_vim_swp(swp_file_path)

    if result:
        print("Metadata:")
        for key, value in result['metadata'].items():
            print(f"{key}: {value}")

        print("\nOriginal File Content:")
        print(result['content'])

##
##
