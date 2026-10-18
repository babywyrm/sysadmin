document.addEventListener('DOMContentLoaded', () => {
  const traceOutput = document.getElementById('trace-output');
  const startTraceButton = document.getElementById('start-trace');
  const clearTraceButton = document.getElementById('clear-trace');

  startTraceButton.addEventListener('click', () => {
    traceOutput.innerHTML = ''; // Clear previous output

    simulateTraceroute();
  });

  clearTraceButton.addEventListener('click', () => {
    traceOutput.innerHTML = ''; // Clear the output
  });

  function simulateTraceroute() {
    const maxHops = 10; // Maximum number of hops to simulate

    for (let hop = 1; hop <= maxHops; hop++) {
      setTimeout(() => {
        const result = `Hop ${hop}: 10.10.69.${hop} (Random Location)`;
        displayTraceResult(result);
      }, hop * 1000); // Delay each hop for 1 second
    }
  }

  function displayTraceResult(result) {
    const resultElement = document.createElement('p');
    resultElement.textContent = result;
    traceOutput.appendChild(resultElement);
  }
});

//
//
