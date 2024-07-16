from ripgrepy import Ripgrepy

def search_keyword(keyword, directory):
    """
    Perform a basic search for a keyword in a directory.

    Args:
        keyword (str): The keyword to search for.
        directory (str): The directory to search in.

    Returns:
        list: The search results.

    Example:
        results = search_keyword('example', '.')
        for result in results:
            print(result)
    """
    return Ripgrepy(keyword, directory).run()

def search_keyword_in_files(keyword, directory, file_types):
    """
    Search for a keyword in specific file types within a directory.

    Args:
        keyword (str): The keyword to search for.
        directory (str): The directory to search in.
        file_types (list): List of file type patterns to include in the search.

    Returns:
        list: The search results.

    Example:
        results = search_keyword_in_files('import', '.', ['*.py'])
        for result in results:
            print(result)
    """
    return Ripgrepy(keyword, directory, glob=file_types).run()

def search_keyword_case_insensitive(keyword, directory):
    """
    Perform a case-insensitive search for a keyword in a directory.

    Args:
        keyword (str): The keyword to search for.
        directory (str): The directory to search in.

    Returns:
        list: The search results.

    Example:
        results = search_keyword_case_insensitive('example', '.')
        for result in results:
            print(result)
    """
    return Ripgrepy(keyword, directory, ignore_case=True).run()

def search_keyword_in_hidden_files(keyword, directory):
    """
    Search for a keyword in hidden files and directories.

    Args:
        keyword (str): The keyword to search for.
        directory (str): The directory to search in.

    Returns:
        list: The search results.

    Example:
        results = search_keyword_in_hidden_files('example', '.')
        for result in results:
            print(result)
    """
    return Ripgrepy(keyword, directory, hidden=True).run()

def search_keyword_with_context(keyword, directory, context_lines=2):
    """
    Search for a keyword and include context lines before and after each match.

    Args:
        keyword (str): The keyword to search for.
        directory (str): The directory to search in.
        context_lines (int): The number of context lines to include before and after each match.

    Returns:
        list: The search results.

    Example:
        results = search_keyword_with_context('example', '.', context_lines=3)
        for result in results:
            print(result)
    """
    return Ripgrepy(keyword, directory, context=context_lines).run()

def search_keyword_with_regex(keyword, directory):
    """
    Perform a regex search for a keyword pattern in a directory.

    Args:
        keyword (str): The regex pattern to search for.
        directory (str): The directory to search in.

    Returns:
        list: The search results.

    Example:
        results = search_keyword_with_regex(r'example\\d+', '.')
        for result in results:
            print(result)
    """
    return Ripgrepy(keyword, directory, regex=True).run()

# Examples of how to use the functions:

# Basic search
# results = search_keyword('example', '.')
# for result in results:
#     print(result)

# Search in specific file types
# results = search_keyword_in_files('import', '.', ['*.py'])
# for result in results:
#     print(result)

# Case-insensitive search
# results = search_keyword_case_insensitive('example', '.')
# for result in results:
#     print(result)

# Search in hidden files
# results = search_keyword_in_hidden_files('example', '.')
# for result in results:
#     print(result)

# Search with context lines
# results = search_keyword_with_context('example', '.', context_lines=3)
# for result in results:
#     print(result)

# Regex search
# results = search_keyword_with_regex(r'example\\d+', '.')
# for result in results:
#     print(result)
