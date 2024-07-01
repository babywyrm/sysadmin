# Use the official Node.js 18 image as the base image
FROM node:18

# Create and set the working directory for the application
WORKDIR /usr/src/app

# Copy package.json and package-lock.json to the working directory
COPY package*.json ./

# Install the application dependencies
RUN npm install

# Copy the rest of the application code to the working directory
COPY . .

# Change the ownership of the working directory to the node user
RUN chown -R node:node /usr/src/app

# Switch to the node user
USER node

# Expose the port the app runs on
EXPOSE 3000

# Command to run the application with NODE_DEBUG environment variable
CMD ["sh", "-c", "NODE_DEBUG=cluster,net,http,fs,tls,module,timers node index.js"]

##
##
