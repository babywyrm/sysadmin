const SECRET_KEY = ENTER YOUR SECRET KEY HERE;
const MAX_TOKENS = 200;

// For more cool AI snippets and demos, follow me on Twitter: https://twitter.com/_abi_
//
//

/**
 * Completes your prompt with GPT-3
 *
 * @param {string} prompt Prompt
 * @param {number} temperature (Optional) Temperature. 1 is super creative while 0 is very exact and precise. Defaults to 0.4.
 * @param {string} model (Optional) GPT-3 Model to use. Defaults to "text-davinci-003".
 * @return Completion returned by GPT-3
 * @customfunction
 */
function AI(prompt, temperature = 0.4, model = "text-davinci-003") {
  const url = "https://api.openai.com/v1/completions";
  const payload = {
    model: model,
    prompt: prompt,
    temperature: temperature,
    max_tokens: MAX_TOKENS,
  };
  const options = {
    contentType: "application/json",
    headers: { Authorization: "Bearer " + SECRET_KEY },
    payload: JSON.stringify(payload),
  };
  const res = JSON.parse(UrlFetchApp.fetch(url, options).getContentText());
  return res.choices[0].text.trim();
}

/**
 * Classifies an item into a fixed set of categories
 * @param {range} categories Set of categories
 * @param {string} item Item to classify
 * @param {range} rules (Optional) Set of rules written in plain text
 * @return Completion returned by GPT-3
 * @customfunction
 */
function CATEGORIZE(categories, input, rules=[]) {
  const prompt = "The available categories are " + categories.map((c) => `"${c}"`).join(", ") + ". " + rules.join(". ") + "The category for '" + input + "' is ";
  console.log(prompt);
  const completion = AI(prompt, 0, "text-davinci-003");
  // Replace "s and .s at the start and end of the string
  return completion.replace(/^"/g, '').replace(/["|.]{0,2}$/, '');
}

// For more cool AI snippets and demos, follow me on Twitter: https://twitter.com/_abi_

//
//
//
