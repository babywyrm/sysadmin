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
