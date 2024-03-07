##
##

import itertools
import string

def remove_punctuation(word):
    # Remove punctuation from the word
    return word.translate(str.maketrans("", "", string.punctuation))

def build_wordlist(email_text):
    # Split the email text into words
    words = [remove_punctuation(word) for word in email_text.split()]

    # Initialize an empty list to store the generated wordlist
    wordlist = []

    # Iterate through the words
    for word in words:
        # Add the word in both uppercase and lowercase
        wordlist.append(word.lower())
        wordlist.append(word.upper())

    # Combine consecutive words when it makes sense (e.g., "Math is life")
    for i in range(len(words) - 1):
        combined_words = words[i] + words[i + 1]
        wordlist.append(combined_words.lower())
        wordlist.append(combined_words.upper())

    # Combine all possible two-word combinations
    two_word_combinations = list(itertools.combinations(words, 2))
    for combination in two_word_combinations:
        combined_two_words = combination[0] + combination[1]
        wordlist.append(combined_two_words.lower())
        wordlist.append(combined_two_words.upper())

    return wordlist

# Example usage with the provided email
##
##

email_text = """
Things
Things
anskfd
lIfe
MNingsa
FDkn
You
Are
Good
At Lifneianfeinaf
Life
Tbh
tbh
yes
indeed
yea
yep
"""

wordlist = build_wordlist(email_text)

# Print the generated wordlist
for word in wordlist:
    print(word)


##
##
