# Base image with Python 3
FROM python:3

# Set the working directory inside the container
WORKDIR /app

# Copy the Python code into the container
COPY slackbot.py .

# Install dependencies
RUN pip install slackclient scikit-learn mysql-connector-python

# Run the Python script
CMD ["python", "slackbot.py"]

###
###
