#!/usr/bin/env python3
"""
Modernized Example Tool

This script demonstrates how to fetch data from an API and process it without
deeply nested loops. It uses list comprehensions and helper functions to keep
the code clean and maintainable.

In this example, we:
  - Fetch coin ticker data from a CoinMarketCap-like API.
  - Extract the coin IDs from the data.
  - Pair each coin ID with its rank (its position in the list).
  - Print the results in a sorted order.

This structure can be adapted to other tasks where you might otherwise use nested loops.
"""

import requests
from typing import List, Tuple


def fetch_ticker_data(api_url: str) -> List[dict]:
    """
    Fetch ticker data from the given API URL.
    
    Raises:
        requests.RequestException: If the HTTP request fails.
    
    Returns:
        A list of dictionaries containing coin data.
    """
    response = requests.get(api_url, timeout=30)
    response.raise_for_status()
    return response.json()


def extract_coin_ids(data: List[dict]) -> List[str]:
    """
    Extract the coin 'id' from each entry in the provided data.
    
    Args:
        data: List of coin data dictionaries.
        
    Returns:
        A list of coin IDs.
    """
    return [item["id"] for item in data if "id" in item]


def pair_ids_with_ranks(ids: List[str]) -> List[Tuple[str, int]]:
    """
    Pair each coin ID with its rank (starting at 1).
    
    Args:
        ids: List of coin IDs.
        
    Returns:
        A list of tuples in the form (coin_id, rank).
    """
    return list(zip(ids, range(1, len(ids) + 1)))


def print_ranked_coins(ranked_coins: List[Tuple[str, int]]) -> None:
    """
    Print the coin IDs and their corresponding ranks.
    
    Args:
        ranked_coins: A list of tuples (coin_id, rank).
    """
    print("Coins and their ranks:")
    for coin_id, rank in ranked_coins:
        print(f"Coin: {coin_id}, Rank: {rank}")


def main() -> None:
    api_url = "https://api.coinmarketcap.com/v1/ticker/"
    try:
        data = fetch_ticker_data(api_url)
    except requests.RequestException as e:
        print(f"Error fetching data: {e}")
        return

    coin_ids = extract_coin_ids(data)
    ranked_coins = pair_ids_with_ranks(coin_ids)

    # Optionally, sort by rank (if needed). In this case, the API is assumed
    # to return coins in rank order so this step is optional.
    ranked_coins.sort(key=lambda x: x[1])
    print_ranked_coins(ranked_coins)


if __name__ == "__main__":
    main()

'''
Explanation
Modular Functions:
Each task (fetching data, extracting IDs, pairing with ranks, printing) is handled in its own function. 
This not only makes the code easier to read and maintain but also allows for unit testing of individual parts.

List Comprehension & zip:
Instead of using nested loops, we extract coin IDs with a single list comprehension and then pair them with their rank using Python’s built-in zip function.

Error Handling:
The fetch_ticker_data function uses raise_for_status() to immediately raise an exception if the API call fails, and the exception is caught in main().

Type Annotations:
Function signatures include type hints to clarify the expected input and output types.                                                        
```                      
