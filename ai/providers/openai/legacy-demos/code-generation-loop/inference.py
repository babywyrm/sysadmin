inference_openai.py

##
##  https://gist.github.com/pszemraj/c643cfe422d3769fd13b97729cf517c5
## 

"""
inference_openai.py - text generation with OpenAI API
    See https://platform.openai.com/docs/quickstart for more details.
Usage:
python inference_openai.py --prompt "The quick brown fox jumps over the lazy dog." --model "gpt-3.5-turbo" --temperature 0.5 --max_tokens 256 --n 1 --stop "."
Detailed usage:
python inference_openai.py --help
Notes:
- The OpenAI API key can be set using the OPENAI_API_KEY environment variable (recommended) or using the --api_key argument.
- This script supports inference with the "chat" models only.
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Union

import fire
import openai
from cleantext import clean
from tqdm.auto import tqdm

AVAILABLE_MODELS = [
    "gpt-4",
    "gpt-4-0314",
    "gpt-4-32k",
    "gpt-4-32k-0314",
    "gpt-3.5-turbo",
    "gpt-3.5-turbo-0301",
    "text-davinci-003",
    "code-davinci-002",
]

logging.basicConfig(
    format="%(asctime)s | %(levelname)s: %(message)s",
    datefmt="%b/%d %H:%M:%S",
    level=logging.INFO,
)


def validate_model(model):
    """
    Validates the given model name against the list of available models (see AVAILABLE_MODELS)
        NOTE: this does not mean you have access to the model, just a basic check.
    :param model: The name of the model to validate.
    :raises ValueError: If the given model is not in the list of available models.
    """
    if model not in AVAILABLE_MODELS:
        raise ValueError(
            f"Invalid model '{model}', available models: {', '.join(AVAILABLE_MODELS)}"
        )


def chat_generate_text(
    prompt: str,
    openai_api_key: str = None,
    model: str = "gpt-3.5-turbo",
    system_prompt: str = "You are a helpful assistant.",
    temperature: float = 0.5,
    max_tokens: int = 256,
    n: int = 1,
    stop: Optional[Union[str, list]] = None,
    presence_penalty: float = 0,
    frequency_penalty: float = 0.1,
) -> List[str]:
    """
    chat_generate_text - Generates text using the OpenAI API.
    :param str prompt: prompt for the model
    :param str openai_api_key: api key for the OpenAI API, defaults to None
    :param str model: model to use, defaults to "gpt-3.5-turbo"
    :param str system_prompt: initial prompt for the model, defaults to "You are a helpful assistant."
    :param float temperature: _description_, defaults to 0.5
    :param int max_tokens: _description_, defaults to 256
    :param int n: _description_, defaults to 1
    :param Optional[Union[str, list]] stop: _description_, defaults to None
    :param float presence_penalty: _description_, defaults to 0
    :param float frequency_penalty: _description_, defaults to 0.1
    :return List[str]: _description_
    """
    if openai_api_key is None:
        openai_api_key = os.environ.get("OPENAI_API_KEY", None)
    assert openai_api_key is not None, "OpenAI API key not found."

    openai.api_key = openai_api_key

    messages = [
        {"role": "system", "content": f"{system_prompt}"},
        {"role": "user", "content": prompt},
    ]

    response = openai.ChatCompletion.create(
        model=model,
        messages=messages,
        temperature=temperature,
        max_tokens=max_tokens,
        n=n,
        stop=stop,
        presence_penalty=presence_penalty,
        frequency_penalty=frequency_penalty,
    )

    generated_texts = [
        choice.message["content"].strip() for choice in response["choices"]
    ]
    return generated_texts


# UTILS


def get_timestamp():
    """Returns the current timestamp in the format YYYYMMDD_HHMM"""
    return datetime.now().strftime("%Y%b%d_%H-%M")


def read_and_clean_file(file_path, lower=False):
    """
    Reads the content of a file and cleans the text using the cleantext package.
    :param file_path: The path to the file.
    :return: The cleaned text.
    """
    with open(file_path, "r", encoding="utf-8") as f:
        context = clean(f.read(), lower=lower)
    return context


def save_output_to_file(
    out_dir,
    output,
    file_name,
):
    """
    Saves the generated output to a file.
    :param out_dir: The output directory.
    :param output: The text to be saved.
    :param file_name: The name of the output file.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    output_file = out_dir / file_name

    with output_file.open("w") as f:
        f.write(output)


def main(
    prompt: Optional[str] = None,
    api_key: Optional[str] = None,
    model: str = "gpt-3.5-turbo",
    system_prompt: str = "You are a helpful assistant.",
    temperature: float = 0.5,
    max_tokens: int = 256,
    n: int = 1,
    stop: Optional[Union[str, list]] = None,
    presence_penalty: float = 0.0,
    frequency_penalty: float = 0.0,
    input_path: Optional[str] = None,
    out_dir: Optional[str] = None,
    save_prompt: bool = False,
    markdown: bool = False,
    verbose: bool = False,
):
    """
    Main function to run the text generation script.
    :param prompt: The input prompt for the model.
    :param api_key: The OpenAI API key. If not provided, checks the environment variable OPENAI_API_KEY.
    :param model: openai model code, defaults to "gpt-3.5-turbo"
    :param system_prompt: The system prompt for the model, defaults to "You are a helpful assistant."
    :param temperature: The sampling temperature (creativity) for the model. (default: 0.5)
    :param max_tokens: The maximum number of tokens in the generated text. (default: 256)
    :param n: The number of generated texts. (default: 1)
    :param stop: The stopping sequence(s) for the model. (default: None)
    :param presence_penalty: The penalty applied for new token presence. (default: 0.0)
    :param frequency_penalty: The penalty applied based on token frequency. (default: 0.0)
    :param file_path: The path to a file/directory to include after the prompt.
    :param out_dir: directory to save outputs. (default: parent directory of input path if provided)
    :param save_prompt: Save the input prompt in the output files with the generated text. (default: False)
    :param markdown: save the generated text as a markdown file. (default: False)
    :param verbose: Whether to print the generated text to the console.
    """
    logger = logging.getLogger(__name__)
    openai.api_key = api_key if api_key else os.getenv("OPENAI_API_KEY")
    assert (
        openai.api_key is not None
    ), "API key not found - pass as arg or set environment variable OPENAI_API_KEY"

    prompts = []
    if input_path:
        prompt = prompt if prompt else ""
        input_path = Path(input_path)
        assert input_path.exists(), f"Path {input_path} does not exist."
        if input_path.is_file():
            logger.info(f"Reading file {input_path}...")
            with open(input_path, "r") as f:
                content = f.read()
            prompts.append(prompt + "\n" + content)
        elif input_path.is_dir():
            for file in input_path.glob("*.txt"):
                with open(file, "r", encoding="utf-8") as f:
                    content = f.read()
                _prompt = prompt + "\n" + content if save_prompt else prompt
                prompts.append(_prompt.strip())

        logger.info(f"read text from {len(prompts)} prompts.")

        # set up output directory
        out_dir = (
            out_dir
            if out_dir
            else input_path.parent
            / f"textgen-{model}-{get_timestamp()}".replace(".", "-")
        )
        logger.info(f"Saving output to {out_dir}...")
    else:
        logger.info(f"No file path provided, using prompt:\t{prompt}")
        prompts.append(prompt)

    assert len(prompts) > 0, "No prompts found."
    validate_model(model)

    logger.info(f"Generating text for {len(prompts)} prompts using model:\t{model}...")
    for i, modified_prompt in enumerate(tqdm(prompts, desc="Generating text"), start=1):
        generated_texts = chat_generate_text(
            prompt=modified_prompt,
            model=model,
            system_prompt=system_prompt,
            temperature=temperature,
            max_tokens=max_tokens,
            n=n,
            stop=stop,
            presence_penalty=presence_penalty,
            frequency_penalty=frequency_penalty,
        )

        if out_dir:
            out_path = Path(out_dir)
            out_path.mkdir(parents=True, exist_ok=True)

        ts = get_timestamp()
        for j, text in enumerate(generated_texts, start=1):
            if verbose or not out_dir:
                print(f"Result {j}:\n{text}")
            if out_dir:
                output_content = (
                    f"## PROMPT\n{modified_prompt}\n## OUTPUT\n{text}"
                    if save_prompt
                    else text
                )  # add prompt to output if save_prompt is True
                output_file = out_path / f"result_{i}_{ts}_{j}.txt"
                output_file = (
                    output_file.with_suffix(".md") if markdown else output_file
                )
                with open(output_file, "w", encoding="utf-8") as f:
                    f.write(output_content)
    # write the parameters to a file if out_dir is provided
    if out_dir:
        with open(out_path / "generation_params.json", "w", encoding="utf-8") as f:
            params = {
                "prompt": prompt,
                "model": model,
                "temperature": temperature,
                "max_tokens": max_tokens,
                "n": n,
                "stop": stop,
                "presence_penalty": presence_penalty,
                "frequency_penalty": frequency_penalty,
                "file_path": input_path,
            }

            params = {
                k: str(v) if not isinstance(v, (int, float)) else v
                for k, v in params.items()
            }
            json.dump(
                params,
                f,
                indent=4,
            )


if __name__ == "__main__":
    fire.Fire(main)


##
##
##


parameters.json
{
    "prompt": "write a poem about the seductiveness of stroopwafels",
    "model": "gpt-3.5-turbo",
    "temperature": 0.5,
    "max_tokens": 256,
    "n": 1,
    "stop": null,
    "presence_penalty": 0,
    "frequency_penalty": 0.1,
    "file_path": null
}


##
##
##



requirements.txt
cleantext
fire
openai
tqdm
result_1_2023Mar18_02-13_1.txt
Oh, how sweet and tempting,
The seductive stroopwafel calls,
With its caramel filling,
And its crispy, buttery walls.

A treat from the Netherlands,
So delicious and divine,
It's hard to resist the allure,
Of this pastry so fine.

The aroma alone,
Is enough to make one swoon,
And once you take a bite,
You'll be over the moon.

The way it melts in your mouth,
Leaves you feeling oh so pleased,
And before you know it,
You've devoured the whole treat with ease.

So beware, my friends,
Of the seductiveness of stroopwafels,
For once you taste their goodness,
You'll be hooked without fail.
