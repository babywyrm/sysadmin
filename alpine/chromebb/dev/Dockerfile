FROM zenika/alpine-chrome:with-puppeteer
  
##
##

USER root

# Install Node.js and npm
RUN apk add --no-cache nodejs npm

# Install Puppeteer globally
RUN npm install -g puppeteer

# Ensure necessary Chrome dependencies are installed
RUN apk add --no-cache \
    udev \
    ttf-freefont \
    chromium

# Create app directory
WORKDIR /usr/src/app

# Create output directory and ensure it's writable
RUN mkdir -p /usr/src/app/output \
    && chown -R chrome:chrome /usr/src/app/output \
    && chmod -R 666 /usr/src/app/output

# Add global npm modules to PATH
ENV PATH=/usr/local/share/.config/yarn/global/node_modules/.bin:$PATH
ENV NODE_PATH=/usr/local/lib/node_modules

# Switch back to the non-root user
USER chrome

# Copy test script into the container
COPY test.js .

# Default command (this can be overridden at runtime)
CMD ["node", "test.js"]

##
##
