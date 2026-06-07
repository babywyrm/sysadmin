FROM zenika/alpine-chrome:with-puppeteer

# Switch to root for package installations
USER root

# Update package index and install necessary tools
RUN apk update && apk add --no-cache \
    nodejs \
    npm \
    firefox \
    firefox-esr \
    bash \
    udev \
    ttf-freefont \
    gtk+3.0 \
    dbus \
    xvfb \
    libnotify \
    alsa-lib

# Install Puppeteer with Firefox support
RUN npm install -g puppeteer puppeteer-firefox

# Create the application directory
WORKDIR /usr/src/app

# Create an output directory with secure permissions
RUN mkdir -p /usr/src/app/output \
    && chown -R chrome:chrome /usr/src/app/output \
    && chmod -R 700 /usr/src/app/output

# Environment variables
ENV PATH="/usr/local/share/.config/yarn/global/node_modules/.bin:$PATH"
ENV NODE_PATH="/usr/local/lib/node_modules"
ENV PUPPETEER_EXECUTABLE_PATH="/usr/bin/firefox"

# Switch back to the non-root user for security
USER chrome

# Copy the test script into the container
COPY test.js .

# Set the default command
CMD ["node", "test.js"]

##
##

# const puppeteer = require('puppeteer-firefox');
#
# (async () => {
#   const browser = await puppeteer.launch({ executablePath: '/usr/bin/firefox' });
#   const page = await browser.newPage();
#    await page.goto('https://example.com');
#    console.log(await page.title());
#    await browser.close();
# })();

# docker build -t firefox-puppeteer .
# docker run --rm -v $(pwd)/output:/usr/src/app/output firefox-puppeteer

##
##
