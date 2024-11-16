## this should work for most webtests
## and you'll get the latest FF/gecko
## you know, probably
##
# Use Debian Bookworm Slim as the base image
FROM debian:bookworm-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget unzip gnupg ca-certificates \
    firefox-esr \
    python3 python3-pip python3-venv \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Download and install GeckoDriver
RUN GECKODRIVER_VERSION=$(curl -s https://api.github.com/repos/mozilla/geckodriver/releases/latest | grep 'tag_name' | cut -d'"' -f4) \
    && wget -q "https://github.com/mozilla/geckodriver/releases/download/$GECKODRIVER_VERSION/geckodriver-$GECKODRIVER_VERSION-linux64.tar.gz" \
    && tar -xzf geckodriver-*-linux64.tar.gz -C /usr/local/bin \
    && rm geckodriver-*-linux64.tar.gz

# Set up a virtual environment for Python
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Selenium in the virtual environment
RUN pip install --no-cache-dir selenium

# Add the application script to the container
WORKDIR /app
COPY . /app

# Set default command to run the Python script
CMD ["python", "selenium_script.py"]

##
##
