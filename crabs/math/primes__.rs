[dependencies]
clap = { version = "4.1", features = ["derive"] }
anyhow = "1.0"

///
///

use anyhow::{Context, Result};
use clap::Parser;
use std::io;

/// Command line options.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// A list of numbers separated by whitespace.
    /// If not provided, the program will read from standard input.
    numbers: Option<Vec<i32>>,
}

/// Checks whether the given number is prime.
///
/// # Examples
///
/// ```
/// assert!(is_prime(7));
/// assert!(!is_prime(9));
/// ```
fn is_prime(n: i32) -> bool {
    if n <= 1 {
        return false;
    }
    if n <= 3 {
        return true;
    }
    if n % 2 == 0 || n % 3 == 0 {
        return false;
    }
    let mut i = 5;
    while i * i <= n {
        if n % i == 0 || n % (i + 2) == 0 {
            return false;
        }
        i += 6;
    }
    true
}

/// Parses input numbers either from command-line arguments or standard input.
fn parse_numbers(args: &Args) -> Result<Vec<i32>> {
    // If numbers were provided as command-line arguments, use them.
    if let Some(ref nums) = args.numbers {
        return Ok(nums.clone());
    }

    // Otherwise, read a line from STDIN.
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .context("Failed to read from standard input")?;

    // Split the input by whitespace and parse into i32.
    let numbers: Vec<i32> = input
        .split_whitespace()
        .map(|s| {
            s.parse::<i32>()
                .with_context(|| format!("Failed to parse '{}' as an integer", s))
        })
        .collect::<Result<Vec<i32>>>()?;
    Ok(numbers)
}

/// Finds two prime numbers in the list and returns their product (the key).
///
/// # Errors
///
/// Returns an error if there are not exactly two prime numbers.
///
/// # Examples
///
/// ```
/// let key = find_key(&[2, 6, 7, 18, 6]).unwrap();
/// assert_eq!(key, 14);
/// ```
fn find_key(numbers: &[i32]) -> Result<i32> {
    let primes: Vec<i32> = numbers.iter().copied().filter(|&n| is_prime(n)).collect();

    if primes.len() != 2 {
        anyhow::bail!(
            "Expected exactly two prime numbers in the input, found {}",
            primes.len()
        )
    }
    Ok(primes[0] * primes[1])
}

fn main() -> Result<()> {
    // Parse command line arguments.
    let args = Args::parse();

    // Parse numbers from input.
    let numbers = parse_numbers(&args)?;

    // Compute the key using the two primes.
    let key = find_key(&numbers)?;
    println!("{}", key);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_prime() {
        let primes = vec![2, 3, 5, 7, 11, 13, 17];
        for &n in &primes {
            assert!(is_prime(n), "{} should be prime", n);
        }
        let non_primes = vec![1, 4, 6, 8, 9, 10, 12];
        for &n in &non_primes {
            assert!(!is_prime(n), "{} should not be prime", n);
        }
    }

    #[test]
    fn test_find_key_success() {
        let numbers = [2, 6, 7, 18, 6];
        let key = find_key(&numbers).expect("Should find 2 primes");
        assert_eq!(key, 14);
    }

    #[test]
    fn test_find_key_error() {
        let numbers = [2, 6, 8, 18, 6]; // Only one prime number (2).
        let result = find_key(&numbers);
        assert!(result.is_err(), "Expected error when not exactly 2 primes");
    }
}
