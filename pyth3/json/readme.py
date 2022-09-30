
Python example - convert text to JSON structure

The Python script below demonstrates how to use regex to match on text with a known structure to build a dictionary, then convert the output to JSON data.

The task comes from this StackOverflow question.

Rather than using a procedural approach to handle the lines one at a time and extract the relevant items, I split the text into chunks and then dealt with each using regex pattern to extract the relevant pieces. Expecting questions A and B to always be present and C and D to be there sometimes.

Note use brackets for capture groups.

(.+)

And use of names for capture groups.

(?<option_a>.+)

Read more info on handling Regex groups in Python - Grouping.

################ ################
################ ################

#!/usr/bin/env python3
import json
import re


PATTERN = re.compile(
    r"""[#]Q (?P<question>.+)\n\^ (?P<answer>.+)\nA (?P<option_a>.+)\nB (?P<option_b>.+)\n(?:C (?P<option_c>.+)\n)?(?:D (?P<option_d>.+))?""",
)

def parse_qa_group(qa_group):
    """
    Extact question, answer and 2 to 4 options from input string and return as a dict.
    """
    matches = PATTERN.search(qa_group)

    question = matches.group('question')
    answer = matches.group('answer')

    a = matches.group('option_a')
    b = matches.group('option_b')

    try:
        c = matches.group('option_c')
    except IndexError:
        c = None
    try:
        d = matches.group('option_d')
    except IndexError:
        d = None

    results = {
        "question": question,
        "answer": answer,
        "a": a,
        "b": b
    }
    if c:
        results['c'] = c

        if d:
            results['d'] = d

    return results


question_answer_str = """\
#Q Three of these animals hibernate. Which one does not?
^ Sloth
A Mouse
B Sloth
C Frog
D Snake

#Q What is the literal translation of the Greek word Embioptera, which denotes an order of insects, also known as webspinners?
^ Lively wings
A Small wings
B None of these
C Yarn knitter
D Lively wings

#Q There is a separate species of scorpions which have two tails, with a venomous sting on each tail.
^ False
A True
B False
"""

# Split into groups using the blank line.
qa_groups = question_answer_str.split('\n\n')

# Process each group, building up a list of all results.
all_results = [parse_qa_group(qa_group) for qa_group in qa_groups]

print(json.dumps(all_results, indent=4))

##
##
