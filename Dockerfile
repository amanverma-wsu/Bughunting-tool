# BugHunter - Dockerfile for Cloud Deployment
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    wget \
    unzip \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Nuclei
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.3.0/nuclei_3.3.0_linux_amd64.zip \
    && unzip nuclei_3.3.0_linux_amd64.zip -d /usr/local/bin/ \
    && rm nuclei_3.3.0_linux_amd64.zip \
    && chmod +x /usr/local/bin/nuclei

# Install Subfinder
RUN wget -q https://github.com/projectdiscovery/subfinder/releases/download/v2.6.3/subfinder_2.6.3_linux_amd64.zip \
    && unzip subfinder_2.6.3_linux_amd64.zip -d /usr/local/bin/ \
    && rm subfinder_2.6.3_linux_amd64.zip \
    && chmod +x /usr/local/bin/subfinder

# Install httpx
RUN wget -q https://github.com/projectdiscovery/httpx/releases/download/v1.6.0/httpx_1.6.0_linux_amd64.zip \
    && unzip httpx_1.6.0_linux_amd64.zip -d /usr/local/bin/ \
    && rm httpx_1.6.0_linux_amd64.zip \
    && chmod +x /usr/local/bin/httpx

# Update Nuclei templates
RUN nuclei -update-templates

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn eventlet

# Copy application code
COPY . .

# Expose port
EXPOSE 8080

# Environment variables
ENV PORT=8080
ENV PYTHONUNBUFFERED=1

# Run with Gunicorn
CMD ["gunicorn", "--worker-class", "eventlet", "-w", "1", "--bind", "0.0.0.0:8080", "bughunter_web:app"]
