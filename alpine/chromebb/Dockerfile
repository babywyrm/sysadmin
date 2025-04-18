# https://github.com/Zenika/alpine-chrome
# Use the Zenika/alpine-chrome image as the base image
#
#
FROM zenika/alpine-chrome

# Install additional packages (if needed)
RUN apk --no-cache add some-package

# Copy any additional configuration files
COPY path/to/your/config /etc/your-app-config

# Set up SECCOMP and AppArmor profiles
# (You'll need to provide your own profiles or use the default profiles)

# Copy SECCOMP profile
COPY path/to/your/seccomp.profile /etc/seccomp/chrome.json

# Copy AppArmor profile
COPY path/to/your/apparmor.profile /etc/apparmor.d/chrome-profile

# Set the environment variable to use the custom SECCOMP profile
ENV SECCOMP_PROFILE /etc/seccomp/chrome.json

# Set the AppArmor profile
ENV APPARMOR_PROFILE /etc/apparmor.d/chrome-profile

# Entry point for your application (if needed)
ENTRYPOINT ["/usr/bin/chromium-browser"]

# Command to run your application (if needed)
CMD ["--no-sandbox", "--disable-gpu", "--headless", "https://example.com"]



###############
###############

FROM alpine:3.18

# Installs latest Chromium package.
RUN apk upgrade --no-cache --available \
    && apk add --no-cache \
      chromium-swiftshader \
      ttf-freefont \
      font-noto-emoji \
    && apk add --no-cache \
      --repository=https://dl-cdn.alpinelinux.org/alpine/edge/community \
      font-wqy-zenhei

COPY local.conf /etc/fonts/local.conf

# Add Chrome as a user
RUN mkdir -p /usr/src/app \
    && adduser -D chrome \
    && chown -R chrome:chrome /usr/src/app
# Run Chrome as non-privileged
USER chrome
WORKDIR /usr/src/app

ENV CHROME_BIN=/usr/bin/chromium-browser \
    CHROME_PATH=/usr/lib/chromium/

# Autorun chrome headless
ENV CHROMIUM_FLAGS="--disable-software-rasterizer --disable-dev-shm-usage"
ENTRYPOINT ["chromium-browser", "--headless"]

###############
###############

Provide SECCOMP and AppArmor Profiles:

Create your own SECCOMP and AppArmor profiles based on the requirements of your application. Ensure that these profiles enhance security without impacting the functionality of your application.

Build the Docker Image:

Run the following command in the directory containing your Dockerfile:

bash
Copy code
docker build -t your-custom-image .
Run the Docker Container:

After successfully building the image, you can run a container based on your custom image:

bash
Copy code
docker run --name your-container -d your-custom-image
Adjust the docker run command according to your application's specific requirements.

Note: It's crucial to carefully craft SECCOMP and AppArmor profiles to balance security and functionality. The provided Dockerfile is a basic template, and you may need to customize it further based on your specific use case and application requirements. Always consider the security implications and thoroughly test the container in your environment.
