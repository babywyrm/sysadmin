// index.js

import init, { evaluate_javascript_code } from './dist/sandbox_project.js';

async function run() {
    await init();

    // JavaScript code to evaluate
    const jsCode = `
        function add(a, b) {
            return a + b;
        }
        add(5, 10);
    `;

    // Call the Rust function to evaluate JavaScript code
    const result = evaluate_javascript_code(jsCode);
    console.log(`Evaluation Result: ${result}`);
}

run();

//

// index.js

import init, { evaluate_javascript_code } from './dist/sandbox_project.js';

async function run() {
    await init();
}

run();

function evaluateCode() {
    const jsCode = document.getElementById('jsCode').value;
    const result = evaluate_javascript_code(jsCode);
    document.getElementById('result').innerText = result;
}

//
//
//
//

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>JavaScript Code Evaluator</title>
</head>
<body>
    <textarea id="jsCode" rows="10" cols="50"></textarea>
    <button onclick="evaluateCode()">Evaluate</button>
    <div id="result"></div>

    <script src="index.js"></script>
</body>
</html>

- The user can paste JavaScript code into a textarea.
- When the "Evaluate" button is clicked, the evaluateCode() function is called.
- This function retrieves the JavaScript code from the textarea, passes it to the Rust WebAssembly module for evaluation, and displays the result on the webpage.

    
