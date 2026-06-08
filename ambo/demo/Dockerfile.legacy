# Use a lightweight Python image.
FROM python:3.9-slim

# Install debugging tools.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      curl \
      bash \
      vim \
      less \
      net-tools \
      iputils-ping && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy and install dependencies.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code.
COPY ext_auth.py .

# Expose port 3000 as expected by Ambassador.
EXPOSE 3000

# Run the ext_auth service.
CMD ["python", "ext_auth.py"]

##
