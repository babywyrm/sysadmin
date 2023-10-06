//
//

const axios = require('axios'); // You may need to install axios if you haven't already

async function evaluateLimitedLines(apiUrl, maxLines) {
  try {
    // Fetch the JavaScript code from the API
    const response = await axios.get(apiUrl);
    const jsCode = response.data;

    // Split the code into lines
    const codeLines = jsCode.split('\n');

    // Limit the number of lines to evaluate
    const linesToEvaluate = codeLines.slice(0, maxLines).join('\n');

    // Evaluate the limited code
    eval(linesToEvaluate);
    
    console.log('JavaScript code evaluated successfully.');

  } catch (error) {
    console.error('Error fetching or evaluating JavaScript:', error);
  }
}

// Usage: Provide the API URL and the maximum number of lines to evaluate
const apiUrl = 'https://api.example.com/jscode';
const maxLines = 10; // Adjust this value to limit the number of lines

evaluateLimitedLines(apiUrl, maxLines);

//
//
