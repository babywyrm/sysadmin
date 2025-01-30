## the easiest thing of all time tbh
## but honestly we love it

# Use an official Python runtime as the base image
FROM python:3.9-slim

# Set the working directory inside the container
WORKDIR /app

# Install system dependencies
RUN apt update && apt install -y curl

# Install Trivy (latest version) properly
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh \
    && mv bin/trivy /usr/local/bin/

# Ensure Trivy is accessible
RUN chmod +x /usr/local/bin/trivy

# Copy the application code
COPY app.py .
COPY templates/ templates/

# Install Python dependencies
RUN pip install Flask

# Expose port for Flask
EXPOSE 6699

# Start the Flask application
CMD ["python", "app.py"]

##
