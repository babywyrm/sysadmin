import pandas as pd
import numpy as np
import re
from typing import List, Union

def create_sample_data():
    """Create sample datasets for demonstration"""
    # Basic DataFrame for substring search examples
    df1 = pd.DataFrame({'col': ['foo', 'foobar', 'bar', 'baz']})
    
    # DataFrame with mixed content including NaN values
    df_mixed = pd.DataFrame({
        'text_col': ['foo abc', 'foobar xyz', np.nan, 'bar32', 'baz 45', 123]
    })
    
    # Multi-column DataFrame for column-wise operations
    df_multi = pd.DataFrame({
        'A': ['foo abc', 'foobar', np.nan, 'bar', 'baz'],
        'B': ['bar xyz', np.nan, 'foo test', 'baz', 'other']
    })
    
    return df1, df_mixed, df_multi

def basic_substring_search(df: pd.DataFrame, column: str, pattern: str, 
                          use_regex: bool = False) -> pd.DataFrame:
    """
    Perform basic substring search with optional regex support
    
    Args:
        df: DataFrame to search
        column: Column name to search in
        pattern: Search pattern/substring
        use_regex: Whether to use regex (default: False for better performance)
    """
    # Use str.contains with explicit regex parameter for clarity
    # Setting regex=False improves performance for simple substring searches
    return df[df[column].str.contains(pattern, regex=use_regex, na=False)]

def multiple_substring_search(df: pd.DataFrame, column: str, 
                             terms: List[str], escape_special: bool = True) -> pd.DataFrame:
    """
    Search for multiple substrings using regex OR pattern
    
    Args:
        df: DataFrame to search
        column: Column name to search in
        terms: List of terms to search for
        escape_special: Whether to escape regex special characters
    """
    # Escape special regex characters if needed to treat them literally
    if escape_special:
        escaped_terms = [re.escape(term) for term in terms]
    else:
        escaped_terms = terms
    
    # Create regex pattern with OR operator (|)
    pattern = '|'.join(escaped_terms)
    
    # Use na=False to handle NaN values gracefully
    return df[df[column].str.contains(pattern, regex=True, na=False)]

def whole_word_search(df: pd.DataFrame, column: str, 
                     terms: Union[str, List[str]]) -> pd.DataFrame:
    """
    Search for complete words using word boundaries
    
    Args:
        df: DataFrame to search
        column: Column name to search in
        terms: Single term or list of terms to search for as whole words
    """
    # Convert single term to list for consistent processing
    if isinstance(terms, str):
        terms = [terms]
    
    # Escape special characters and add word boundaries (\b)
    escaped_terms = [re.escape(term) for term in terms]
    pattern = r'\b(?:{})\b'.format('|'.join(escaped_terms))
    
    return df[df[column].str.contains(pattern, regex=True, na=False)]

def apply_search_to_multiple_columns(df: pd.DataFrame, pattern: str, 
                                   columns: List[str] = None) -> pd.DataFrame:
    """
    Apply substring search across multiple columns
    
    Args:
        df: DataFrame to search
        pattern: Search pattern
        columns: List of columns to search (None for all object columns)
    """
    # Select object/string columns if no specific columns provided
    if columns is None:
        columns = df.select_dtypes(include=['object']).columns.tolist()
    
    # Apply search column-wise using lambda function
    # axis=1 applies function across columns for each row
    search_results = df[columns].apply(
        lambda col: col.str.contains(pattern, na=False), axis=0
    )
    
    return search_results

def check_string_existence(df: pd.DataFrame, column: str, 
                          search_value: str, exact_match: bool = False) -> dict:
    """
    Check if string exists in column and provide statistics
    
    Args:
        df: DataFrame to search
        column: Column name to search in
        search_value: Value to search for
        exact_match: Whether to perform exact match or substring search
    """
    if exact_match:
        # Check for exact string matches using eq() method
        mask = df[column].eq(search_value)
        exists = mask.any()
        count = mask.sum()
    else:
        # Check for partial string matches using str.contains()
        mask = df[column].str.contains(search_value, na=False)
        exists = mask.any()
        count = mask.sum()
    
    return {
        'exists': exists,
        'count': count,
        'percentage': (count / len(df)) * 100
    }

def list_comprehension_search(df: pd.DataFrame, column: str, 
                            pattern: str, use_regex: bool = False) -> pd.DataFrame:
    """
    Alternative search method using list comprehensions (often faster)
    
    Args:
        df: DataFrame to search
        column: Column name to search in
        pattern: Search pattern
        use_regex: Whether to use regex pattern matching
    """
    if use_regex:
        # Compile regex pattern for better performance with repeated use
        compiled_pattern = re.compile(pattern, flags=re.IGNORECASE)
        
        # Use list comprehension with try/except for NaN handling
        mask = []
        for value in df[column]:
            try:
                mask.append(bool(compiled_pattern.search(str(value))))
            except (TypeError, AttributeError):
                mask.append(False)
    else:
        # Simple substring search using 'in' operator
        mask = [pattern in str(value) if pd.notna(value) else False 
                for value in df[column]]
    
    return df[mask]

def vectorized_search_methods(df: pd.DataFrame, column: str, pattern: str) -> dict:
    """
    Demonstrate various vectorized search methods for performance comparison
    
    Args:
        df: DataFrame to search
        column: Column name to search in
        pattern: Search pattern (substring only for np.char methods)
    """
    results = {}
    
    # Method 1: pandas str.contains (most common)
    results['pandas_str_contains'] = df[
        df[column].str.contains(pattern, na=False)
    ]
    
    # Method 2: numpy char.find (substring only, no regex)
    char_find_mask = np.char.find(
        df[column].values.astype(str), pattern
    ) > -1
    results['numpy_char_find'] = df[char_find_mask]
    
    # Method 3: np.vectorize with custom function
    vectorized_func = np.vectorize(
        lambda x: pattern in str(x) if pd.notna(x) else False
    )
    vectorized_mask = vectorized_func(df[column])
    results['numpy_vectorize'] = df[vectorized_mask]
    
    return results

# Demonstration usage
if __name__ == "__main__":
    # Create sample data
    df1, df_mixed, df_multi = create_sample_data()
    
    print("=== Basic Substring Search ===")
    # Search for 'foo' in basic DataFrame
    result1 = basic_substring_search(df1, 'col', 'foo', use_regex=False)
    print(result1)
    
    print("\n=== Multiple Substring Search ===")
    # Search for multiple terms with automatic escaping
    terms = ['foo', 'baz']
    result2 = multiple_substring_search(df_mixed, 'text_col', terms)
    print(result2)
    
    print("\n=== Whole Word Search ===")
    # Search for complete words only
    df_text = pd.DataFrame({
        'text': ['the sky is blue', 'bluejay by the window', 'blue car']
    })
    result3 = whole_word_search(df_text, 'text', 'blue')
    print(result3)
    
    print("\n=== String Existence Check ===")
    # Check if string exists and get statistics
    stats = check_string_existence(df_mixed, 'text_col', 'foo', exact_match=False)
    print(f"Pattern exists: {stats['exists']}")
    print(f"Occurrence count: {stats['count']}")
    print(f"Percentage: {stats['percentage']:.1f}%")
    
    print("\n=== Multi-column Search ===")
    # Apply search across multiple columns
    multi_results = apply_search_to_multiple_columns(df_multi, 'foo')
    print(multi_results)
    
    print("\n=== Performance Comparison ===")
    # Compare different search methods (for larger datasets)
    large_df = pd.concat([df_mixed] * 1000, ignore_index=True)
    
    # Timing comparison would go here in practice
    # %timeit basic_substring_search(large_df, 'text_col', 'foo')
    # %timeit list_comprehension_search(large_df, 'text_col', 'foo')
