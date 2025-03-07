const NIGHT_MODE_ID = 'night-mode-styles';
const NIGHT_MODE_KEY = 'nightModeEnabled';

document.addEventListener('DOMContentLoaded', () => {
  if (localStorage.getItem(NIGHT_MODE_KEY) === 'true') {
    enableNightMode();
  }
});

document.getElementById('nightModeToggle').addEventListener('click', () => {
  toggleNightMode();
});

function toggleNightMode() {
  const existingStyle = document.getElementById(NIGHT_MODE_ID);
  if (existingStyle) {
    disableNightMode();
  } else {
    enableNightMode();
  }
}

function enableNightMode() {
  const styleEl = document.createElement('style');
  styleEl.id = NIGHT_MODE_ID;
  styleEl.textContent = `
    body {
      filter: invert(1) hue-rotate(180deg);
      background: #000;
    }
    iframe, img, video {
      filter: invert(1) hue-rotate(180deg);
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
  const existingStyle = document.getElementById(NIGHT_MODE_ID);
  if (existingStyle) {
    existingStyle.remove();
  }
  localStorage.removeItem(NIGHT_MODE_KEY);
}

