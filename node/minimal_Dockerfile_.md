```# Use a minimal Alpine Linux as the base image

FROM alpine:latest

# Set environment variables for Node.js
ENV NODE_VERSION 14.17.5
ENV NPM_VERSION 6.14.14

# Create a non-root user for running the Node.js application
RUN adduser -D -u 1000 nodejsapp

# Install dependencies required for running Node.js
RUN apk --no-cache add \
    nodejs=${NODE_VERSION}-r0 \
    npm=${NPM_VERSION}-r0 \
    su-exec

# Create a directory for your Node.js application
WORKDIR /app

# Copy your Node.js application code into the container
COPY . .

# Set the ownership of the application directory to the non-root user
RUN chown -R nodejsapp:nodejsapp /app

# Drop root privileges and switch to the non-root user for running the application
USER nodejsapp

# Expose the port your Node.js application listens on (change this as needed)
EXPOSE 3000

# Define the command to start your Node.js application
CMD ["node", "app.js"]



```
Explanation:

We start with the latest Alpine Linux base image, which is minimal in size to reduce the attack surface.

We set environment variables for Node.js and NPM versions to ensure we install specific versions.

We create a non-root user named nodejsapp with UID 1000 to run the Node.js application, improving security.

Necessary dependencies for Node.js and NPM are installed using the apk package manager.

We create a directory for your Node.js application (/app) and copy the application code into it.

Ownership of the /app directory is set to the nodejsapp user to prevent unauthorized access.

We switch to the nodejsapp user using USER to run the Node.js application as a non-root user.

The container is configured to expose the port (change it as needed) that your Node.js application listens on.

Finally, the CMD instruction specifies the command to start your Node.js application.

Remember to replace "app.js" in the CMD with the appropriate entry point or startup script for your Node.js application.

Build your Docker image using this Dockerfile:

bash
Copy code
docker build -t secure-nodejs-app .
And then, you can run your secure Node.js application using:

bash
Copy code
docker run -p 3000:3000 secure-nodejs-app
