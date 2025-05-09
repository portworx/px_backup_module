FROM python:3.9-slim

# Update packages and install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip and install Python packages
RUN pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir ansible-core requests PyYAML kubernetes

# Install the px_backup Ansible collection
RUN ansible-galaxy collection install purepx.px_backup

# Create a working directory and copy your script
WORKDIR /app
COPY . /app

# Set the default command to display usage
CMD ["tail", "-f", "/dev/null"]
