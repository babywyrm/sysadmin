
##
#
https://github.com/k4l1sh/WordlistGPT
#
##


WordlistGPT Example
Features

    Use of ChatGPT to generate related words.
    Fast generation of uppercase variations, l33t variations and character insertions.
    Customizable word sizes, batch saving, and more.

Usage

Try wordlistgpt.py with 'harry potter':

git clone https://github.com/k4l1sh/WordlistGPT.git
cd WordlistGPT
python wordlistgpt.py -w 'harry potter'

You can also run directly from url if you are feeling lazy:

curl -sSL https://raw.githubusercontent.com/k4l1sh/WordlistGPT/main/wordlistgpt.py | python - -w 'harry potter'

A file named wordlist.txt will be created with the generated wordlist.

To take advantage of ChatGPT to generate related words, you need to get an OpenAI API key from OpenAI API keys.

After getting an OpenAI API key, create an .env file with API_KEY=your_openai_api_key_here or run the script with OpenAI API key in the arguments --key your_openai_api_key_here.
Wordlist Generation Process

The Wordlist Generator follows a systematic process to generate a wordlist that is suitable for different purposes. Here's a step-by-step breakdown of how the wordlist is created:

    Words from GPT:
        For each word in the user-specified list, the generator makes an API call to OpenAI GPT, requesting related words.
        The generator adds the response from GPT to the wordlist.

    Word Cleaning and Adjusting:
        Subwords from each word are split and added to the wordlist.
        Non-word characters within the wordlist are stripped off, ensuring only clean words remain.

    Uppercase Variations:
        For each word in the wordlist, variations are created by changing the case of the characters.
        The variations are added to the wordlist

    Leet Variations:
        Leet variations are generated based on a predefined leet mapping.
        For each word in the wordlist, variations with leet characters are added to the wordlist.

    Insert Deterministic Characters:
        Deterministic characters, which are predefined sets of characters, can be inserted in the wordlist words.
        These characters can be added to the left, right, or nested within the words based on user-defined positions.

    Insert Random Characters:
        Random characters from a defined charset can be inserted into the words at random positions.
        The number of random insertions and the level of randomness are both defined by user parameters.

Argument Details

    -w, --words: Words to generate the wordlist for
    -n, --number: Number of words to generate in ChatGPT for each word. (default: 20)
    -min, --min-size: Minimum number of characters for each word. (default: 6)
    -max, --max-size: Maximum number of characters for each word. (default: 14)
    -m, --max-words: Maximum number of words in the wordlist if not batched. (default: 10000000)
    -b, --batch_size: Batch size for wordlist processing. (default: 1000000)
    -d, --deterministic-chars: Number of deterministic characters to be added. (default: 2)
    -dc, --deterministic-charset: Charset of deterministic characters to be added. (default: '0123456789_!@$%#')
    -dp, --deterministic-position: Position for inserting deterministic characters (default: ['left', 'right'])
    -u, --uppercase: Maximum number of characters to convert to uppercase in each word. (default: inf)
    -l, --leet: Maximum number of leet characters to replace in each word. (default: inf)
    -lm, --leet-mapping: JSON-formatted leet mapping dictionary. (default: provided)
    -r, --random-chars: Maximum number of random characters to be added. (default: 0)
    -rc, --random-charset: Charset of characters to be randomly added. (default: '0123456789!@$&+_-.?/+;#')
    -rl, --random-level: Number of iterations of random characters to be added. (default: 1)
    -rw, --random-weights: Weights for determining position of random character insertion. (default: 0.47, 0.47, 0.06)
    -k, --key: OpenAI API Key. (default: None)
    -o, --output: Output file for the generated wordlist. (default: wordlist.txt)
    -v, --debug: If True, enable debug logging. (default: False)
    -s, --silent: If True, disable logging. (default: False)

Examples
Basic usage with related words to "harry potter"

    Default configurations with 2 deterministic character insertions instead of 1

python wordlistgpt.py -w 'harry potter' -d 2

Output:

grep 'DumBl3doRe_9' wordlist.txt && wc -l wordlist.txt && du -h wordlist.txt

DumBl3doRe_9
100300392   wordlist.txt
1,3G        wordlist.txt

Amount of variations of "voldemort":

grep -i "voldemort" wordlist.txt | wc -l && grep -i "voldemort" wordlist.txt | shuf -n 5

279040
vOlDEMORt$%
voldeMoRt23
VoLdEMoRt6$
vOldEMORt76
vOldEMOrt25

Generate 50 words related to "love" with some modifications

    Get 50 words related to "love" from ChatGPT.
    Words can have at least 4 characters.
    Apply a maximum of 2 uppercase and leet variations.

python wordlistgpt.py -w 'love' -n 50 -min 4 --uppercase 2 --leet 2 -d 2

Output:

grep '@_romance' wordlist.txt && wc -l wordlist.txt && du -h wordlist.txt

@_romance
4352133 wordlist.txt
50M     wordlist.txt

Create wordlist from "change" with characters insertions in the right

    Base word: "change"
    No related words from ChatGPT.
    No random characters insertion.
    Add up to 5 deterministic characters from the charset '0123456789_!@$%#' to be added only in the right.

python wordlistgpt.py -w 'change' -n 0 -d 5 -dc '0123456789_!@$%#' -dp 'right'

Output:

grep 'cH4nG3@123!' wordlist.txt && wc -l wordlist.txt && du -h wordlist.txt

cH4nG3@123!
483183576   wordlist.txt
5,4G        wordlist.txt

Create only AI and cybersecurity related words

    Get 200 words each related to "artificial intelligence" and "cybersecurity".
    Limit words to 30 characters.
    Remove all leet, uppercase, deterministic and random characters variations.
    Save the list to "ai_wordlist.txt".

python wordlistgpt.py -w 'artificial intelligence' 'cybersecurity ' -n 200 -max 30 -u 0 -l 0 -d 0 -r 0 -o ai_wordlist.txt

Output:

echo $(head -n 20 ai_wordlist.txt | tr '\n' ' ') && wc -w ai_wordlist.txt && du -h ai_wordlist.txt

activity activityrecognition advanced advancedpersistentthreat agentbasedmodeling agents algorithm algorithms analysis analyst analytics anomaly anomalydetection antivirus application applications applicationsecuritytesting architectures artificial artificialcreativity artificialintelligence artificialintelligenceethics artificialneuralnetworks assessment assistant assistants assisted attack augmented augmentedreality
531     ai_wordlist.txt
8,0K    ai_wordlist.txt

Create wordlist from "qwerty" with deterministic insertions

    Base word: "qwerty"
    No related words from ChatGPT.
    Remove leet and random variations
    Add up to 3 deterministic characters from the charset 'abcdefghijklmnopqrstuvwxyz0123456789_!@$%#' to be added in the left and right.
    Save the results in "qwerty_wordlist.txt".

python wordlistgpt.py -w qwerty -n 0 -l 0 -d 3 -dc 'abcdefghijklmnopqrstuvwxyz0123456789_!@$%#' -o qwerty_wordlist.txt

Output:

grep 'QweRtY_$%' qwerty_wordlist.txt && wc -w qwerty_wordlist.txt && du -h qwerty_wordlist.txt

QweRtY_$%
9714496 qwerty_wordlist.txt
93M     qwerty_wordlist.txt

Custom wordlist from "0123456789" with random insertions

    Base word: "0123456789"
    Add up to 3 random characters from "!@#$%" iterating this process 999 times, inserting it only in the end.

python wordlistgpt.py -w '0123456789' -n 0 -d 0 --random-chars 3 --random-charset '!@#$%' --random-level 999 --random-weights 0 1 0

Output:

grep '0123456789!@@' wordlist.txt && wc -w wordlist.txt && du -h wordlist.txt

0123456789!@@
142     wordlist.txt
4,0K    wordlist.txt

Create wordlist from "admin"

    Base word: "admin".
    Do not fetch related words from ChatGPT.
    Create all leet and uppercase variations
    Add up to 1 deterministic characters from the charset 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_!@$%#&'.
    Positions for deterministic characters: left, right, and nested in the left and right.
    No random character variations.

python wordlistgpt.py -w 'admin' -n 0 -dc 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_!@$%#&' -dp left -dp right -dp nested

Output:

grep '%4dMiN_' wordlist.txt && wc -w wordlist.txt && du -h wordlist.txt

%4dMiN_
352728  wordlist.txt
2,7M    wordlist.txt

Create wordlist for words related to "marvel" running from URL

    Fetch and run the script directly from URL.
    Generate words related to "marvel" using default configurations.
    Use your OpenAI API key in the arguments.

curl -sSL https://raw.githubusercontent.com/k4l1sh/WordlistGPT/main/wordlistgpt.py | python3 - -w marvel -k your_openai_api_key_here

grep 'Av3nG3rs_' wordlist.txt && wc -w wordlist.txt && du -h wordlist.txt

Av3nG3rs_
10597968    wordlist.txt
144M        wordlist.txt

Contributing

Contributions are welcome! Please feel free to submit pull requests or raise issues.
License

This project is licensed under the MIT License. See the LICENSE file for details.
About

A python script to generate custom wordlists using GPT
Topics
wordlist openai wordlist-generator chatgpt
Resources
Readme
License
MIT license
Activity
Stars
6 stars
Watchers
3 watching
Forks
0 forks
Report repository
Releases 4
1.2.1 Latest
Dec 3, 2023
+ 3 releases
Packages
No packages published
Languages

    Python 100.0% 

Footer
© 2024 GitHub, Inc.
Footer navigation

    Terms
    Privacy
    Security
    Status
    Docs
    Contact

