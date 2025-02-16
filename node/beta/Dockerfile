# Use a minimal Node.js image
FROM node:18-slim

# Install Chromium, git, openssh-client, and dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    chromium \
    git \
    openssh-client \
    ca-certificates \
    fonts-liberation \
    libnss3 \
    libx11-6 \
    libx11-data \
    libxcb1 \
    libxcomposite1 \
    libxcursor1 \
    libxdamage1 \
    libxi6 \
    libxtst6 \
    libxrandr2 \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

# Set environment variables for temporary directories so all temp/cache files go to /tmp
ENV TMPDIR=/tmp
ENV HOME=/tmp
# Force Selenium/Chrome to use our dedicated cache directory
RUN mkdir -p /tmp/cache && chmod 777 /tmp/cache
ENV XDG_CACHE_HOME=/tmp/cache

# Disable Selenium Manager so it doesn't try to write to a protected area
ENV SELENIUM_MANAGER=0

# (Optional) Tell Selenium where chromedriver is installed from npm
ENV webdriver.chrome.driver=/app/node_modules/chromedriver/bin/chromedriver

# Create a dedicated directory for HAR logs
RUN mkdir -p /har
VOLUME ["/har"]

# Set working directory
WORKDIR /app

# Copy package files and the local tarball into /app
COPY package*.json ./
COPY chrome-har-capturer-0.14.1.tgz ./

# Install dependencies
RUN npm install --production

# Ensure chromedriver binary is executable
RUN chmod +x ./node_modules/chromedriver/bin/chromedriver

# Copy the Node.js application code
COPY index.js .

# Expose port 3000 (the app listens on this port)
EXPOSE 3000

# Create and switch to a non-root user for improved security
RUN useradd -m appuser
USER appuser

# Start the Node.js application
CMD ["node", "index.js"]
