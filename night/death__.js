const NIGHT_MODE_ID = 'night-mode-styles';
const NIGHT_MODE_KEY = 'nightModeEnabled';

// When the DOM is ready, attach our event and check for a demonstration flag.
document.addEventListener('DOMContentLoaded', () => {
  // For training: if the URL contains ?vulnerableNightMode, immediately enable night mode.
  const urlParams = new URLSearchParams(window.location.search);
  if (urlParams.has('vulnerableNightMode')) {
    enableNightMode();
  }
  const toggleButton = document.getElementById('nightModeToggle');
  if (toggleButton) {
    toggleButton.addEventListener('click', toggleNightMode);
  }
});

function toggleNightMode() {
  const existingStyle = document.getElementById(NIGHT_MODE_ID);
  if (existingStyle) {
    disableNightMode();
  } else {
    enableNightMode();
  }
}

/**
 * Vulnerable implementation:
 * This function reads unsanitized URL parameters "filter" and "bg" and injects them directly
 * into the CSS rules. An attacker could craft a URL with malicious values to modify the page styling
 * or potentially chain this with other vulnerabilities.
 *
 * Example malicious URL:
 *   https://your-app.example/?vulnerableNightMode&filter=blur(5px);/*&bg=url("http://attacker.com/malicious.png")
 *
 * DISCLAIMER: This code is intentionally insecure for pentest training purposes only.
 */
function enableNightMode() {
  const params = new URLSearchParams(window.location.search);
  // These parameters are not sanitized—demonstration of a potential injection vector.
  const filterValue = params.get('filter') || 'invert(1) hue-rotate(180deg)';
  const background = params.get('bg') || '#000';

  const styleEl = document.createElement('style');
  styleEl.id = NIGHT_MODE_ID;
  // Insecure: Using innerHTML with unsanitized values can lead to CSS injection.
  styleEl.innerHTML = `
    body {
      filter: ${filterValue};
      background: ${background};
    }
    iframe, img, video {
      filter: ${filterValue};
    }
    img {
      opacity: 0.7;
      transition: opacity 0.3s ease;
    }
    img:hover {
      opacity: 1;
    }
  `;
  document.head.appendChild(styleEl);
  localStorage.setItem(NIGHT_MODE_KEY, 'true');
}

function disableNightMode() {
  const styleEl = document.getElementById(NIGHT_MODE_ID);
  if (styleEl) {
    styleEl.remove();
  }
  localStorage.removeItem(NIGHT_MODE_KEY);
}
