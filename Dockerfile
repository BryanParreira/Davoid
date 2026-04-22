# Dockerfile
FROM python:3.11-slim

# Install system dependencies required for networking and security tools
RUN apt-get update && apt-get install -y \
    nmap \
    iproute2 \
    gcc \
    python3-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Create necessary directories
RUN mkdir -p logs payloads plugins reports

# Set python path
ENV PYTHONPATH=/app

# Entry point
ENTRYPOINT ["python", "main.py"]