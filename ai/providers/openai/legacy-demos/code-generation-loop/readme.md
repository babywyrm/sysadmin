README.MD
https://twitter.com/mattcduff

##
#
https://gist.github.com/RodgerE1/9339c6ea0c851e48d41b852b80834d98
#
##

This is blowing my mind.

I built a quick #GPT4 program that creates its own code -> runs it -> bug fixes it -> and then adds new features to it... continuously... on loop... by itself. It just keeps on building 🤯

Literally creating software as you sleep. pic.twitter.com/g5YMExUJWJ

— Matt Duff (@mattcduff) April 2, 2023
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>
THIS IS NOT MY CODE, I received it freely from Matt Duff. He was offing the code out for free.

I'm not going to change anything in this, so go ahead and copy and modify.

OpenAI-Code-Gen-and-Execution
This Python script utilizes the OpenAI API to generate Python code based on user prompts, execute the generated code, check for errors, and suggest new features while ensuring their correctness.

Features
Generate Python code using the OpenAI API
Execute the generated code and check for errors
Request new features from the OpenAI API
Add new features to the code and ensure their correctness
Requirements
Python 3.6 or higher
An OpenAI API key
Installation
Clone the repository:

Change the directory to the project folder:

Install the required packages:

Usage
Replace the "YOUR API KEY HERE" placeholder with your OpenAI API key in the openai.api_key variable.

Run the script:

Follow the prompts to generate and execute Python code.

License
This project is licensed under the MIT License - see the LICENSE file for details.

```
main-code.py
import os
import openai
import subprocess
import sys

# Configure the OpenAI API
openai.api_key = ("YOUR API KEY HERE")

def get_code_from_openai(prompt):
    response = openai.Completion.create(
        engine="text-davinci-004",
        prompt=prompt,
        max_tokens=2000,
        n=1,
        stop=None,
        temperature=0.7,
    )

    return response.choices[0].text.strip()

def execute_code(code, timeout=10):
    with open("temp_code.py", "w") as f:
        f.write(code)

    try:
        result = subprocess.run([sys.executable, "temp_code.py"], capture_output=True, text=True, check=True, timeout=timeout)
        return result.stdout, False
    except subprocess.CalledProcessError as e:
        return e.stdout + e.stderr, True
    except subprocess.TimeoutExpired:
        return "Execution timed out.", True

def request_new_feature(code):
    prompt = f"The following Python code is working without errors:\n\n{code}\n\n Please generate a brand new feature that is different from the existing code and provide the Python code for it. Write a concise feature scope in comments before the new code."
    new_feature_code = get_code_from_openai(prompt)
    return new_feature_code

def main():
    previous_feature = ""
    while True:
        prompt = "Write code for a python program that finds funny things on the internet and adds them to a CSV"
        error_exists = True
        while error_exists:
            print("Generating code using OpenAI API...")
            # Generate code using OpenAI API
            code = get_code_from_openai(prompt)
            print("Executing the code and checking for errors...")

            # Execute the code and capture the output
            output, error_exists = execute_code(code)
            if error_exists:
                print("Errors found, sending output to GPT-4 for fixing...")
                # Send the output to GPT-4 to fix the errors
                prompt = f"The following Python code has some errors:\n\n{code}\n\nError message:\n{output}\n\nPlease fix the errors and provide the corrected code."
        while not error_exists:
            print("No errors found. Requesting a new feature...")
            # When there are no errors, ask GPT to suggest a new feature
            new_feature = request_new_feature(code)
            print("Adding new feature to the code and checking for errors...")

            # Add the new feature to the code and check for errors again
            code += "\n\n" + new_feature
            output, error_exists = execute_code(code)
            if error_exists:
                print("Errors found in the new feature, sending output to GPT-4 for fixing...")
                # Send the output to GPT-4 to fix the errors in the new feature
                prompt = f"The following Python code has some errors after adding the new feature:\n\n{code}\n\nError message:\n{output}\n\nPlease fix the errors and provide the corrected code."

if __name__ == "__main__":
    main()
```

##
##
##
##
OpenAI-Code-Gen-and-Execution
